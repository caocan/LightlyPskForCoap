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
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.scandium.auth.PreSharedKeyIdentity;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
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

	/**
	 * The last flight that is sent during this handshake, will not be
	 * retransmitted unless the peer retransmits its last flight.
	 */
	private DTLSFlight lastFlight;

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

        if (lastFlight != null) {
            // we already sent the last flight (including our FINISHED message),
            // but the client does not seem to have received it because we received
            // its finished message again, so we simply retransmit our last flight
            LOGGER.log(Level.FINER, "Received server's ({0}) FINISHED message again, retransmitting last flight...",
                    getPeerAddress());
            lastFlight.incrementTries();
            lastFlight.setNewSequenceNumbers();
            recordLayer.sendFlight(lastFlight);
            return;
        }

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
                // 当发送完第二次的ClientHello之后，希望下一次Flight中服务器
                // 能发送一个ChangeCipherSpec消息
                expectChangeCipherSpecMessage();
				break;

			case SERVER_HELLO:
				receivedServerHello((ServerHello) handshakeMsg);
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
            if (lastFlight == null) {
                // only increment for ongoing handshake flights, not for the last flight!
                // not ignore a client FINISHED retransmission caused by lost server FINISHED
                incrementNextReceiveSeq();
            }
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

        // 查看如果是最后一次航班，那么就返回，不是才发送
        if (lastFlight != null) {
            return;
        }

        DTLSFlight flight = new DTLSFlight(getSession());

        MessageDigest mdWithServerFinished = null;

        try {
            /**
             * 将ServerFinished消息也加入到摘要计算中，之后发送给服务器，让服务器进行完整性验证
             */
            mdWithServerFinished = (MessageDigest) md.clone();
        } catch (CloneNotSupportedException e) {
            throw new HandshakeException(
                    "Cannot create FINISHED message",
                    new AlertMessage(
                            AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, message.getPeer()));
        }

        byte[] handshakeHash = md.digest();
        // 对于ClientFinish之前所有的消息进行哈希，然后进行完整性验证
        message.verifyData(session.getMasterSecret(), false, handshakeHash);

		mdWithServerFinished.update(message.toByteArray());

        /*
         * 2. 发送ChangeCipherSpec
         */
        ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(session.getPeer());
        flight.addMessage(wrapMessage(changeCipherSpecMessage));
        // 设置当前写状态
        setCurrentWriteState();

        /*
         * 3. 发送Finished message，将ServerFinished消息加入哈希
         */
        handshakeHash = mdWithServerFinished.digest();
        Finished finished = new Finished(getMasterSecret(), true, handshakeHash, session.getPeer());
        flight.addMessage(wrapMessage(finished));

        state = HandshakeType.FINISHED.getCode();

        flight.setRetransmissionNeeded(false);
        // store, if we need to retransmit this flight, see
        // http://tools.ietf.org/html/rfc6347#section-4.2.4
        lastFlight = flight;
        recordLayer.sendFlight(flight);
        // 会话建立好了，可以发送应用层消息了
        sessionEstablished();
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
        // 将客户端的PSK密钥库中所有的identity都添加到ClientHello中的identity列表
        for (String identity : pskStore.getAllIdentity())
            clientHello.AddToIdentityList(identity);
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

		// 用于存储预主密钥
		byte[] premasterSecret;

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

		// 获取到服务器协商好的密钥
		String identity = serverHello.getIdentity();

		// 获取到服务器random，这样两个随机数就齐全了
		serverRandom = serverHello.getRandom();

		// 查找psk
		byte[] psk = pskStore.getKey(identity);
		if (psk == null) {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL,	AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
			throw new HandshakeException("No preshared secret found for identity: " + identity, alert);
		}
		session.setPeerIdentity(new PreSharedKeyIdentity(identity));

		LOGGER.log(Level.FINER, "Using PSK identity: {0}", identity);
		premasterSecret = generatePremasterSecretFromPSK(psk);
		// 计算出会话密钥
		generateKeys(premasterSecret);
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
