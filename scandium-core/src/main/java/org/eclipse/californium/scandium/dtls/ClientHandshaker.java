/*******************************************************************************
 * Copyright (c) 2015 - 2017 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Stefan Jucker - DTLS implementation
 *    Kai Hudalla (Bosch Software Innovtions GmbH) - small improvements
 *    Kai Hudalla (Bosch Software Innovations GmbH) - store peer's identity in session as a
 *                                                    java.security.Principal (fix 464812)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - notify SessionListener about start and completion
 *                                                    of handshake
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix 475112: only prefer RawPublicKey from server
 *                                                    if no trust store has been configured
 *    Kai Hudalla (Bosch Software Innovations GmbH) - consolidate and fix record buffering and message re-assembly
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace Handshaker's compressionMethod and cipherSuite
 *                                                    properties with corresponding properties in DTLSSession
 *    Kai Hudalla (Bosch Software Innovations GmbH) - derive max fragment length from network MTU
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use SessionListener to trigger sending of pending
 *                                                    APPLICATION messages
 *    Achim Kraus (Bosch Software Innovations GmbH) - use isSendRawKey also for 
 *                                                    supportedServerCertificateTypes
 *    Ludwig Seitz (RISE SICS) - Updated calls to verifyCertificate() after refactoring
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.auth.PreSharedKeyIdentity;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * ClientHandshaker does the protocol handshaking from the point of view of a
 * client. It is driven by handshake messages as delivered by the parent
 * {@link Handshaker} class.
 */
public class ClientHandshaker extends Handshaker {

	private static final Logger LOGGER = Logger.getLogger(ClientHandshaker.class.getName());

	// Members ////////////////////////////////////////////////////////

	private ProtocolVersion maxProtocolVersion = new ProtocolVersion();

	/** The server's public key from its certificate */
	// 服务器来自证书的公钥
	private PublicKey serverPublicKey;
	
	// The server's X.509 certificate chain.
	// 服务器的X.509证书链
	private CertPath peerCertPath;

	/** The server's ephemeral public key, used for key agreement */
	// 服务器的临时公钥，用于密钥协商
	private ECPublicKey ephemeralServerPublicKey;

	/** The client's hello handshake message. Store it, to add the cookie in the second flight. */
	protected ClientHello clientHello = null;

	/** the preferred cipher suites ordered by preference */
	private final CipherSuite[] preferredCipherSuites;

	protected Integer maxFragmentLengthCode;

	/*
	 * Store all the message which can possibly be sent by the server. We need
	 * these to compute the handshake hash.
	 */
	/** The server's {@link ServerHello}. Mandatory. */
	protected ServerHello serverHello;
	/** The server's {@link ServerKeyExchange}. Optional. */
	protected ServerKeyExchange serverKeyExchange = null;
	/** The server's {@link ServerHelloDone}. Mandatory. */
	protected ServerHelloDone serverHelloDone;

	/** The hash of all received handshake messages sent in the finished message. */
	protected byte[] handshakeHash = null;

	/** Used to retrieve identity/pre-shared-key for a given destination */
	protected final PskStore pskStore;
	protected final ServerNameResolver serverNameResolver;
	protected ServerNames indicatedServerNames;
	protected SignatureAndHashAlgorithm negotiatedSignatureAndHashAlgorithm;
    
	// Constructors ///////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a server.
	 * 
	 * @param session
	 *            the session to negotiate with the server.
	 * @param recordLayer
	 *            the object to use for sending flights to the peer.
	 * @param sessionListener
	 *            the listener to notify about the session's life-cycle events.
	 * @param config
	 *            the DTLS configuration.
	 * @param maxTransmissionUnit
	 *            the MTU value reported by the network interface the record layer is bound to.
	 * @throws IllegalStateException
	 *            if the message digest required for computing the FINISHED message hash cannot be instantiated.
	 * @throws NullPointerException
	 *            if session, recordLayer or config is <code>null</code>
	 */
	public ClientHandshaker(DTLSSession session, RecordLayer recordLayer, SessionListener sessionListener,
			DtlsConnectorConfig config, int maxTransmissionUnit) {
		super(true, session, recordLayer, sessionListener, config.getTrustStore(), maxTransmissionUnit);
		this.privateKey = config.getPrivateKey();
		this.certificateChain = config.getCertificateChain();
		this.publicKey = config.getPublicKey();
		this.pskStore = config.getPskStore();
		this.serverNameResolver = config.getServerNameResolver();
		this.preferredCipherSuites = config.getSupportedCipherSuites();
		this.maxFragmentLengthCode = config.getMaxFragmentLengthCode();
	}

	// Methods ////////////////////////////////////////////////////////

	final SignatureAndHashAlgorithm getNegotiatedSignatureAndHashAlgorithm() {
		return negotiatedSignatureAndHashAlgorithm;
	}

	@Override
	protected synchronized void doProcessMessage(DTLSMessage message) throws HandshakeException, GeneralSecurityException {

		// log record now (even if message is still encrypted) in case an Exception
		// is thrown during processing
		if (LOGGER.isLoggable(Level.FINE)) {
			StringBuilder msg = new StringBuilder();
			msg.append(String.format(
					"Processing %s message from peer [%s]",
					message.getContentType(), message.getPeer()));
			if (LOGGER.isLoggable(Level.FINEST)) {
				msg.append(":").append(System.lineSeparator()).append(message);
			}
			LOGGER.fine(msg.toString());
		}
		
		switch (message.getContentType()) {
		case ALERT:
			break;

		case CHANGE_CIPHER_SPEC:
			// TODO check, if all expected messages already received
			setCurrentReadState();
			LOGGER.log(Level.FINE, "Processed {1} message from peer [{0}]",
					new Object[]{message.getPeer(), message.getContentType()});
			break;

		case HANDSHAKE:
			HandshakeMessage handshakeMsg = (HandshakeMessage) message;

			switch (handshakeMsg.getMessageType()) {
			case HELLO_REQUEST:
				receivedHelloRequest();
				break;

			case HELLO_VERIFY_REQUEST:
				receivedHelloVerifyRequest((HelloVerifyRequest) handshakeMsg);
				break;

			case SERVER_HELLO:
				receivedServerHello((ServerHello) handshakeMsg);
				break;


			case SERVER_HELLO_DONE:
				receivedServerHelloDone((ServerHelloDone) handshakeMsg);
				expectChangeCipherSpecMessage();
				break;

			case FINISHED:
				receivedServerFinished((Finished) handshakeMsg);
				break;

			default:
				throw new HandshakeException(
						String.format("Received unexpected handshake message [%s] from peer %s", handshakeMsg.getMessageType(), handshakeMsg.getPeer()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE, handshakeMsg.getPeer()));
			}

			// 写一个序列号加1，这样就会
			incrementNextReceiveSeq();
			LOGGER.log(Level.FINE, "Processed {1} message with sequence no [{2}] from peer [{0}]",
					new Object[]{handshakeMsg.getPeer(), handshakeMsg.getMessageType(), handshakeMsg.getMessageSeq()});
			break;

		default:
			throw new HandshakeException(
					String.format("Received unexpected message [%s] from peer %s", message.getContentType(), message.getPeer()),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, message.getPeer()));
		}
	}

	/**
	 * Called when the client received the server's finished message. If the
	 * data can be verified, encrypted application data can be sent.
	 * 
	 * @param message
	 *            the {@link Finished} message.
	 * @throws HandshakeException
	 * @throws GeneralSecurityException if the APPLICATION record cannot be created 
	 */
	private void receivedServerFinished(Finished message) throws HandshakeException, GeneralSecurityException {

		message.verifyData(getMasterSecret(), false, handshakeHash);
		state = HandshakeType.FINISHED.getCode();
		sessionEstablished();
		handshakeCompleted();
	}

	/**
	 * Used by the server to kickstart negotiations.
	 *
	 * @throws HandshakeException if the CLIENT_HELLO record cannot be created
	 */
	private void receivedHelloRequest() throws HandshakeException {
		if (state < HandshakeType.HELLO_REQUEST.getCode()) {
			startHandshake();
		} else {
			// already started with handshake, drop this message
		}
	}

	/**
	 * A {@link HelloVerifyRequest} is sent by the server upon the arrival of
	 * the client's {@link ClientHello}. It is sent by the server to prevent
	 * flooding of a client. The client answers with the same
	 * {@link ClientHello} as before with the additional cookie.
	 * 
	 * @param message
	 *            the server's {@link HelloVerifyRequest}.
	 * @throws HandshakeException if the CLIENT_HELLO record cannot be created
	 */
	protected void receivedHelloVerifyRequest(HelloVerifyRequest message) throws HandshakeException {

		clientHello.setCookie(message.getCookie());
		// update the length (cookie added)
		clientHello.setFragmentLength(clientHello.getMessageLength());

		DTLSFlight flight = new DTLSFlight(getSession());
		flight.addMessage(wrapMessage(clientHello));
		// {@link org.eclipse.californium.scandium.DTLSConnector.sendHandshakeFlight}
		recordLayer.sendFlight(flight);
	}

	/**
	 * Stores the negotiated security parameters.
	 * 存储协商好的安全参数
	 * 
	 * @param message
	 *            the {@link ServerHello} message.
	 * @throws HandshakeException if the ServerHello message cannot be processed,
	 * 	e.g. because the server selected an unknown or unsupported cipher suite
	 */
	protected void receivedServerHello(ServerHello message) throws HandshakeException {
		if (serverHello != null && (message.getMessageSeq() == serverHello.getMessageSeq())) {
			// received duplicate version (retransmission), discard it
			// 收到重复的报文，应该丢弃
			return;
		}
		serverHello = message;

		// store the negotiated values
		usedProtocol = message.getServerVersion();
		serverRandom = message.getRandom();
		session.setSessionIdentifier(message.getSessionId());
		session.setCipherSuite(message.getCipherSuite());
		session.setCompressionMethod(message.getCompressionMethod());
		if (message.getMaxFragmentLength() != null) {
			MaxFragmentLengthExtension.Length maxFragmentLength = message.getMaxFragmentLength().getFragmentLength(); 
			if (maxFragmentLength.code() == maxFragmentLengthCode) {
				// immediately use negotiated max. fragment size
				session.setMaxFragmentLength(maxFragmentLength.length());
			} else {
				throw new HandshakeException(
						"Server wants to use other max. fragment size than proposed",
						new AlertMessage(
								AlertLevel.FATAL,
								AlertDescription.ILLEGAL_PARAMETER,
								message.getPeer()));
			}
		}
	}

	/**
	 * The ServerHelloDone message is sent by the server to indicate the end of
	 * the ServerHello and associated messages. The client prepares all
	 * necessary messages (depending on server's previous flight) and returns
	 * the next flight.
	 * 
	 * @throws HandshakeException
	 * @throws GeneralSecurityException if the client's handshake records cannot be created
	 */
	private void receivedServerHelloDone(ServerHelloDone message) throws HandshakeException, GeneralSecurityException {

		if (serverHelloDone != null && (serverHelloDone.getMessageSeq() == message.getMessageSeq())) {
			// discard duplicate message
			return;
		}
		serverHelloDone = message;
		DTLSFlight flight = new DTLSFlight(getSession());


		/*
		 * Second, send ClientKeyExchange as specified by the key exchange
		 * algorithm.
		 */
		ClientKeyExchange clientKeyExchange;
		byte[] premasterSecret;
		switch (getKeyExchangeAlgorithm()) {
		case EC_DIFFIE_HELLMAN:
			clientKeyExchange = new ECDHClientKeyExchange(ecdhe.getPublicKey(), session.getPeer());
			premasterSecret = ecdhe.getSecret(ephemeralServerPublicKey).getEncoded();
			generateKeys(premasterSecret);
			break;
		case PSK:
			String identity = pskStore.getIdentity(getPeerAddress());
			if (identity == null) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
				throw new HandshakeException("No Identity found for peer: "	+ getPeerAddress(), alert);
			}
			byte[] psk = pskStore.getKey(identity);
			if (psk == null) {
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL,	AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
				throw new HandshakeException("No preshared secret found for identity: " + identity, alert);
			}
			session.setPeerIdentity(new PreSharedKeyIdentity(identity));
			clientKeyExchange = new PSKClientKeyExchange(identity, session.getPeer());
			LOGGER.log(Level.FINER, "Using PSK identity: {0}", identity);
			premasterSecret = generatePremasterSecretFromPSK(psk);
			generateKeys(premasterSecret);

			break;

		case NULL:
			clientKeyExchange = new NULLClientKeyExchange(session.getPeer());

			// We assume, that the premaster secret is empty
			generateKeys(new byte[] {});
			break;

		default:
			throw new HandshakeException(
					"Unknown key exchange algorithm: " + getKeyExchangeAlgorithm(),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer()));
		}
		flight.addMessage(wrapMessage(clientKeyExchange));


		/*
		 * Fourth, send ChangeCipherSpec
		 */
		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(session.getPeer());
		flight.addMessage(wrapMessage(changeCipherSpecMessage));
		// 一组算法和相应的安全参数，它们一起表示TLS连接的当前读取或写入状态。
		setCurrentWriteState();

		/*
		 * Fifth, send the finished message.
		 */
		// create hash of handshake messages
		// can't do this on the fly, since there is no explicit ordering of
		// messages
		md.update(clientHello.toByteArray());
		md.update(serverHello.toByteArray());

		if (serverKeyExchange != null) {
			md.update(serverKeyExchange.toByteArray());
		}

		md.update(serverHelloDone.toByteArray());

		md.update(clientKeyExchange.toByteArray());


		MessageDigest mdWithClientFinished = null;
		try {
			mdWithClientFinished = (MessageDigest) md.clone();
		} catch (CloneNotSupportedException e) {
			throw new HandshakeException(
					"Cannot create FINISHED message",
					new AlertMessage(
							AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, message.getPeer()));
		}

		handshakeHash = md.digest();
		Finished finished = new Finished(getMasterSecret(), isClient, handshakeHash, session.getPeer());
		flight.addMessage(wrapMessage(finished));

		// compute handshake hash with client's finished message also
		// included, used for server's finished message
		mdWithClientFinished.update(finished.toByteArray());
		handshakeHash = mdWithClientFinished.digest();

		recordLayer.sendFlight(flight);
	}


	@Override
	public void startHandshake() throws HandshakeException {
		handshakeStarted();
		// 新建一个ClientHello消息，这是第一次创建ClientHello消息，所以没有Cookie
		ClientHello startMessage = new ClientHello(maxProtocolVersion, new SecureRandom(),session.getPeer());

		// 存储客户端随机数（clientRandom），用于后期计算
		clientRandom = startMessage.getRandom();

		// preferredCipherSuites按照所支持的密钥套件的优先顺序来添加
		for (CipherSuite supportedSuite : preferredCipherSuites) {
			startMessage.addCipherSuite(supportedSuite);
		}

		// ClientHello消息不进行压缩算法
		startMessage.addCompressionMethod(CompressionMethod.NULL);
		if (maxFragmentLengthCode != null) {
			MaxFragmentLengthExtension ext = new MaxFragmentLengthExtension(maxFragmentLengthCode); 
			startMessage.addExtension(ext);
			LOGGER.log(
					Level.FINE,
					"Indicating max. fragment length [{0}] to server [{1}]",
					new Object[]{maxFragmentLengthCode, getPeerAddress()});
		}

		// 将服务器名字添加到ClientHello消息中
		addServerNameIndication(startMessage);

		// 设置当前state，也就是当前消息类型对应的code(1)
		state = startMessage.getMessageType().getCode();

		// 存储这个消息，用于后期计算（MAC）
		clientHello = startMessage;
		// 根据已经建立的客户端会话，创建一个DTLSFlight
		DTLSFlight flight = new DTLSFlight(session);
		// 将刚刚创建好的ClientHello消息包装到一个或多个record中
		// 然后将这个record列表添加到一次DTLSFlight中
		flight.addMessage(wrapMessage(startMessage));

		// 会调用{org.eclipse.californium.scandium.DTLSConnector.sendHandshakeFlight}
		recordLayer.sendFlight(flight);
	}

	// 将服务器名字添加到ClientHello消息中
	private void addServerNameIndication(final ClientHello helloMessage) {

		if (serverNameResolver != null) {
			indicatedServerNames = serverNameResolver.getServerNames(session.getPeer());
			if (indicatedServerNames != null) {
				helloMessage.addExtension(ServerNameExtension.forServerNames(indicatedServerNames));
			}
		}
	}
}
