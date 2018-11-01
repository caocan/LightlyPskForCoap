/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - small improvements
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 *    Kai Hudalla (Bosch Software Innovations GmbH) - store peer's identity in session as a
 *                                                    java.security.Principal (fix 464812)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for stale
 *                                                    session expiration (466554)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - notify SessionListener about start and completion
 *                                                    of handshake
 *    Kai Hudalla (Bosch Software Innovations GmbH) - only include client/server certificate type extensions
 *                                                    in SERVER_HELLO if required for cipher suite
 *    Kai Hudalla (Bosch Software Innovations GmbH) - pick arbitrary supported group if client omits
 *                                                    Supported Elliptic Curves Extension (fix 473678)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - consolidate and fix record buffering and message re-assembly
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace Handshaker's compressionMethod and cipherSuite
 *                                                    properties with corresponding properties in DTLSSession
 *    Kai Hudalla (Bosch Software Innovations GmbH) - derive max fragment length from network MTU
 *    Kai Hudalla (Bosch Software Innovations GmbH) - support MaxFragmentLength Hello extension sent by client
 *    Achim Kraus (Bosch Software Innovations GmbH) - don't ignore retransmission of last flight
 *    Achim Kraus (Bosch Software Innovations GmbH) - use isSendRawKey also for 
 *                                                    supportedClientCertificateTypes
 *    Ludwig Seitz (RISE SICS) - Updated calls to verifyCertificate() after refactoring                                                   
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.eclipse.californium.scandium.auth.PreSharedKeyIdentity;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.util.ByteArrayUtils;
import org.eclipse.californium.scandium.util.ServerNames;

/**
 * Server handshaker does the protocol handshaking from the point of view of a
 * server. It is message-driven by the parent {@link Handshaker} class.
 */
public class ServerHandshaker extends Handshaker {

	private static final Logger LOGGER = Logger.getLogger(ServerHandshaker.class.getName());

	// Members ////////////////////////////////////////////////////////

	/**
	 * The last flight that is sent during this handshake, will not be
	 * retransmitted unless the peer retransmits its last flight.
	 */
	private DTLSFlight lastFlight;

	/** Is the client required to authenticate itself? */
	private boolean clientAuthenticationRequired = false;

	/**
	 * The cryptographic options this server supports, e.g. for exchanging keys,
	 * digital signatures etc.
	 */
	private List<CipherSuite> supportedCipherSuites;

	private SupportedGroup negotiatedSupportedGroup;
	private SignatureAndHashAlgorithm signatureAndHashAlgorithm;
	private ServerNames indicatedServerNames;

	/*
	 * Store all the messages which can possibly be sent by the client. We
	 * need these to compute the handshake hash.
	 */

	/** The client's {@link ClientKeyExchange}. mandatory. */
	protected ClientKeyExchange clientKeyExchange;

	/** Used to retrieve pre-shared-key from a given client identity */
	protected final PskStore pskStore;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Creates a handshaker for negotiating a DTLS session with a client
	 * following the full DTLS handshake protocol. 
	 * 
	 * @param session
	 *            the session to negotiate with the client.
	 * @param recordLayer
	 *            the object to use for sending flights to the peer.
	 * @param sessionListener
	 *            the listener to notify about the session's life-cycle events.
	 * @param config
	 *            the DTLS configuration.
	 * @param maxTransmissionUnit
	 *            the MTU value reported by the network interface the record layer is bound to.
	 * @throws HandshakeException if the handshaker cannot be initialized
	 * @throws NullPointerException
	 *            if session or recordLayer is <code>null</code>.
	 */
	public ServerHandshaker(DTLSSession session, RecordLayer recordLayer, SessionListener sessionListener,
			DtlsConnectorConfig config, int maxTransmissionUnit) throws HandshakeException {
		this(0, session, recordLayer, sessionListener, config, maxTransmissionUnit);
	}
	
	/**
	 * Creates a handshaker for negotiating a DTLS session with a client
	 * following the full DTLS handshake protocol. 
	 * 
	 * @param initialMessageSequenceNo
	 *            the initial message sequence number to expect from the peer
	 *            (this parameter can be used to initialize the <em>receive_next_seq</em>
	 *            counter to another value than 0, e.g. if one or more cookie exchange round-trips
	 *            have been performed with the peer before the handshake starts).
	 * @param session
	 *            the session to negotiate with the client.
	 * @param recordLayer
	 *            the object to use for sending flights to the peer.
	 * @param sessionListener
	 *            the listener to notify about the session's life-cycle events.
	 * @param config
	 *            the DTLS configuration.
	 * @param maxTransmissionUnit
	 *            the MTU value reported by the network interface the record layer is bound to.
	 *            
	 * @throws IllegalStateException
	 *            if the message digest required for computing the FINISHED message hash cannot be instantiated.
	 * @throws IllegalArgumentException
	 *            if the <code>initialMessageSequenceNo</code> is negative.
	 * @throws NullPointerException
	 *            if session, recordLayer or config is <code>null</code>.
	 */
	public ServerHandshaker(int initialMessageSequenceNo, DTLSSession session, RecordLayer recordLayer, SessionListener sessionListener,
			DtlsConnectorConfig config, int maxTransmissionUnit) { 
		super(false, initialMessageSequenceNo, session, recordLayer, sessionListener, config.getTrustStore(), maxTransmissionUnit);

		this.supportedCipherSuites = Arrays.asList(config.getSupportedCipherSuites());

		this.pskStore = config.getPskStore();

		this.privateKey = config.getPrivateKey();
		this.certificateChain = config.getCertificateChain();
		this.publicKey = config.getPublicKey();

		this.clientAuthenticationRequired = config.isClientAuthenticationRequired();

	}

	// Methods ////////////////////////////////////////////////////////


	@Override
	protected synchronized void doProcessMessage(DTLSMessage message) throws HandshakeException, GeneralSecurityException {
		if (lastFlight != null) {
			// we already sent the last flight (including our FINISHED message),
			// but the client does not seem to have received it because we received
			// its finished message again, so we simply retransmit our last flight
			LOGGER.log(Level.FINER, "Received client's ({0}) FINISHED message again, retransmitting last flight...",
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
		case CHANGE_CIPHER_SPEC:
			setCurrentReadState();
			LOGGER.log(Level.FINE, "Processed {1} message from peer [{0}]",
					new Object[]{message.getPeer(), message.getContentType()});
			break;

		case HANDSHAKE:
			HandshakeMessage handshakeMsg = (HandshakeMessage) message;

			switch (handshakeMsg.getMessageType()) {
			case CLIENT_HELLO:
				receivedClientHello((ClientHello) handshakeMsg);
				break;

			case CLIENT_KEY_EXCHANGE:
				byte[] premasterSecret;
				switch (getKeyExchangeAlgorithm()) {
				case PSK:
					premasterSecret = receivedClientKeyExchange((PSKClientKeyExchange) handshakeMsg);
					generateKeys(premasterSecret);
					break;

				case NULL:
					premasterSecret = receivedClientKeyExchange((NULLClientKeyExchange) handshakeMsg);
					generateKeys(premasterSecret);
					break;

				default:
					throw new HandshakeException(
							String.format("Unsupported key exchange algorithm %s", getKeyExchangeAlgorithm().name()),
							new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, handshakeMsg.getPeer()));
				}
				handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, clientKeyExchange.getRawMessage());

				if (!clientAuthenticationRequired || getKeyExchangeAlgorithm() != KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN) {
					expectChangeCipherSpecMessage();
				}
				break;


			case FINISHED:
				receivedClientFinished((Finished) handshakeMsg);
				break;

			default:
				throw new HandshakeException(
						String.format("Received unexpected %s message from peer %s", handshakeMsg.getMessageType(), handshakeMsg.getPeer()),
						new AlertMessage(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE, handshakeMsg.getPeer()));
			}

			if (lastFlight == null) {
				// only increment for ongoing handshake flights, not for the last flight!
				// not ignore a client FINISHED retransmission caused by lost server FINISHED
				incrementNextReceiveSeq();
			}
			LOGGER.log(Level.FINE, "Processed {1} message with message sequence no [{2}] from peer [{0}]",
					new Object[]{message.getPeer(), handshakeMsg.getMessageType(), handshakeMsg.getMessageSeq()});
			break;

		default:
			throw new HandshakeException(
					String.format("Received unexpected %s message from peer %s", message.getContentType(), message.getPeer()),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, message.getPeer()));
		}
	}


	/**
	 * Called, when the server received the client's {@link Finished} message.
	 * Generate a {@link DTLSFlight} containing the
	 * {@link ChangeCipherSpecMessage} and {@link Finished} message. This flight
	 * will not be retransmitted, unless we receive the same finish message in
	 * the future; then, we retransmit this flight.
	 * 
	 * @param message
	 *            the client's {@link Finished} message.
	 * @throws HandshakeException if the client did not send the required <em>CLIENT_CERTIFICATE</em>
	 *            and <em>CERTIFICATE_VERIFY</em> messages or if the server's FINISHED message
	 *            cannot be created
	 */
	private void receivedClientFinished(Finished message) throws HandshakeException {
		if (lastFlight != null) {
			return;
		}

		DTLSFlight flight = new DTLSFlight(getSession());


		md.update(clientKeyExchange.getRawMessage()); // mandatory

		MessageDigest mdWithClientFinished = null;
		try {
			/*
			 * the handshake_messages for the Finished message sent by the
			 * client will be different from that for the Finished message sent
			 * by the server, because the one that is sent second will include
			 * the prior one.
			 */
			mdWithClientFinished = (MessageDigest) md.clone();
			mdWithClientFinished.update(message.toByteArray());
		} catch (CloneNotSupportedException e) {
			LOGGER.log(Level.SEVERE, "Cannot compute digest for server's Finish handshake message", e);
		}

		// Verify client's data
		byte[] handshakeHash = md.digest();
		// 对于ClientFinish之前所有的消息进行哈希，然后进行完整性验证
		message.verifyData(getMasterSecret(), true, handshakeHash);

		/*
		 * First, send ChangeCipherSpec
		 */
		ChangeCipherSpecMessage changeCipherSpecMessage = new ChangeCipherSpecMessage(session.getPeer());
		flight.addMessage(wrapMessage(changeCipherSpecMessage));
		setCurrentWriteState();

		/*
		 * Second, send Finished message，将客户度的Finish消息加入哈希
		 */
		handshakeHash = mdWithClientFinished.digest();
		Finished finished = new Finished(getMasterSecret(), isClient, handshakeHash, session.getPeer());
		flight.addMessage(wrapMessage(finished));

		state = HandshakeType.FINISHED.getCode();

		flight.setRetransmissionNeeded(false);
		// store, if we need to retransmit this flight, see
		// http://tools.ietf.org/html/rfc6347#section-4.2.4
		lastFlight = flight;
		recordLayer.sendFlight(flight);
		sessionEstablished();
	}

	/**
	 * Called after the server receives a {@link ClientHello} handshake message.
	 * 
	 * Prepares the next flight (mandatory messages depend on the cipher suite / key exchange
	 * algorithm). Mandatory messages are ServerHello and ServerHelloDone; see
	 * <a href="http://tools.ietf.org/html/rfc5246#section-7.3">Figure 1.
	 * Message flow for a full handshake</a> for details about the messages in
	 * the next flight.
	 * 
	 * @param clientHello
	 *            the client's hello message.
	 * @throws HandshakeException if the server's response message(s) cannot be created
	 */
	private void receivedClientHello(final ClientHello clientHello) throws HandshakeException {

		handshakeStarted();
		DTLSFlight flight = new DTLSFlight(getSession());

		// update the handshake hash
		md.update(clientHello.getRawMessage());
		handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, clientHello.getRawMessage());

		createServerHello(clientHello, flight);

		/*
		 * Last, send ServerHelloDone (mandatory)
		 */
		ServerHelloDone serverHelloDone = new ServerHelloDone(session.getPeer());
		flight.addMessage(wrapMessage(serverHelloDone));
		md.update(serverHelloDone.toByteArray());
		handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverHelloDone.toByteArray());

		recordLayer.sendFlight(flight);
	}

	private void createServerHello(final ClientHello clientHello, final DTLSFlight flight) throws HandshakeException {

		ProtocolVersion serverVersion = negotiateProtocolVersion(clientHello.getClientVersion());

		// store client and server random
		clientRandom = clientHello.getRandom();
		serverRandom = new Random();

		// 生成一个sessionId，设置到当前的session
		SessionId sessionId = new SessionId();
		session.setSessionIdentifier(sessionId);

		// 目前只支持NULL压缩，无需协商
		if (!clientHello.getCompressionMethods().contains(CompressionMethod.NULL)) {
			// abort handshake
			throw new HandshakeException(
					"Client does not support NULL compression method",
					new AlertMessage(
							AlertLevel.FATAL,
							AlertDescription.HANDSHAKE_FAILURE,
							clientHello.getPeer()));
		} else {
			session.setCompressionMethod(CompressionMethod.NULL);
		}

		HelloExtensions serverHelloExtensions = new HelloExtensions();
		negotiateCipherSuite(clientHello, serverHelloExtensions);

		MaxFragmentLengthExtension maxFragmentLengthExt = clientHello.getMaxFragmentLengthExtension();
		if (maxFragmentLengthExt != null) {
			session.setMaxFragmentLength(maxFragmentLengthExt.getFragmentLength().length());
			serverHelloExtensions.addExtension(maxFragmentLengthExt);
			LOGGER.log(
					Level.FINE,
					"Negotiated max. fragment length [{0} bytes] with peer [{1}]",
					new Object[]{maxFragmentLengthExt.getFragmentLength().length(), clientHello.getPeer()});
		}

		ServerNameExtension serverNameExt = clientHello.getServerNameExtension();
		if (serverNameExt != null) {
			// 存储由peer指示的名称，以便在密钥交换期间供以后参考
			indicatedServerNames = serverNameExt.getServerNames();
			serverHelloExtensions.addExtension(ServerNameExtension.emptyServerNameIndication());
			LOGGER.log(
					Level.FINE,
					"Using server name indication received from peer [{1}]",
					clientHello.getPeer());
		}

		ServerHello serverHello = new ServerHello(serverVersion, serverRandom, sessionId,
				session.getCipherSuite(), session.getCompressionMethod(), serverHelloExtensions, session.getPeer());
		flight.addMessage(wrapMessage(serverHello));

		// update the handshake hash
		md.update(serverHello.toByteArray());
		handshakeMessages = ByteArrayUtils.concatenate(handshakeMessages, serverHello.toByteArray());
	}

	/**
	 * Retrieves the preshared key from the identity hint and then generates the
	 * premaster secret.
	 * 
	 * @param message
	 *            the client's key exchange message.
	 * @return the premaster secret
	 * @throws HandshakeException
	 *             if no specified preshared key available.
	 */
	private byte[] receivedClientKeyExchange(final PSKClientKeyExchange message) throws HandshakeException {

		clientKeyExchange = message;
		byte[] psk = null;

		// use the client's PSK identity to get right preshared key
		String identity = message.getIdentity();

		LOGGER.log(Level.FINER, "Client [{0}] uses PSK identity [{1}]",
				new Object[]{getPeerAddress(), identity});

		if (getIndicatedServerNames() == null) {
			psk = pskStore.getKey(identity);
		} else {
			psk = pskStore.getKey(getIndicatedServerNames(), identity);
		}

		if (psk == null) {
			throw new HandshakeException(
					String.format("Cannot authenticate client, identity [%s] is unknown", identity),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer()));
		} else {
			session.setPeerIdentity(new PreSharedKeyIdentity(identity));
			return generatePremasterSecretFromPSK(psk);
		}
	}

	/**
	 * Returns an empty premaster secret.
	 * 
	 * @param message
	 *            the client's key exchange message.
	 * @return the premaster secret
	 */
	private byte[] receivedClientKeyExchange(NULLClientKeyExchange message) {
		clientKeyExchange = message;

		// by current assumption we take an empty premaster secret
		// to compute the master secret and the resulting keys
		return new byte[] {};
	}

	@Override
	public void startHandshake() throws HandshakeException {
		HelloRequest helloRequest = new HelloRequest(session.getPeer());

		DTLSFlight flight = new DTLSFlight(getSession());
		flight.addMessage(wrapMessage(helloRequest));
		recordLayer.sendFlight(flight);
	}

	/**
	 * Negotiates the version to be used. It will return the lower of that
	 * suggested by the client in the client hello and the highest supported by
	 * the server.
	 * 
	 * @param clientVersion
	 *            the suggested version by the client.
	 * @return the version to be used in the handshake.
	 * @throws HandshakeException
	 *             if the client's version is smaller than DTLS 1.2
	 */
	private ProtocolVersion negotiateProtocolVersion(ProtocolVersion clientVersion) throws HandshakeException {
		ProtocolVersion version = new ProtocolVersion();
		if (clientVersion.compareTo(version) >= 0) {
			return new ProtocolVersion();
		} else {
			AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.PROTOCOL_VERSION, session.getPeer());
			throw new HandshakeException("The server only supports DTLS v1.2", alert);
		}
	}

	/**
	 * Selects one of the client's proposed cipher suites.
	 * <p>
	 * Iterates through the provided (ordered) list of the client's
	 * preferred ciphers until one is found that is also contained
	 * in the {@link #supportedCipherSuites}.
	 * </p>
	 * <p>
	 * If the client proposes an ECC based cipher suite this method also
	 * tries to determine an appropriate <em>Supported Group</em> by means
	 * of invoking the {@link #negotiateNamedCurve(ClientHello)} method.
	 * If a group is found it will be stored in the {@link #negotiatedSupportedGroup}
	 * field. 
	 * </p>
	 * <p>
	 * The selected cipher suite is set on the <em>session</em>  to be negotiated
	 * using the {@link DTLSSession#setCipherSuite(CipherSuite)} method. The
	 * <em>negotiatedServerCertificateType</em>, <em>negotiatedClientCertificateType</em>
	 * and <em>negotiatedSupportedGroup</em> fields are set to values corresponding to
	 * the selected cipher suite.
	 * </p>
	 * <p>
	 * The <em>SSL_NULL_WITH_NULL_NULL</em> cipher suite is <em>never</em>
	 * negotiated as mandated by <a href="http://tools.ietf.org/html/rfc5246#appendix-A.5">
	 * RFC 5246 Appendix A.5</a>
	 * </p>
	 * 
	 * @param clientHello
	 *            the <em>CLIENT_HELLO</em> message containing the list of cipher suites
	 *            the client supports (ordered by preference).
	 * @param serverHelloExtensions
	 *            the container object to add server extensions to that are required for the selected
	 *            cipher suite.
	 * @throws HandshakeException
	 *             if this server's configuration does not support any of the cipher suites
	 *             proposed by the client.
	 */

	/**
	 * 选择客户端建议的密码套件之一。
	 *
	 * 迭代客户端提供的首选密钥套件的（有序）列表，直到找到一个也包含在{@link #supportedCipherSuites}中的密钥套件。
	 * 如果客户端提出基于ECC的密码套件，则此方法还尝试通过调用{@link #negotiateNamedCurve(ClientHello)} 方法来
	 * 确定适当的Supported Group。如果找到一个组，它将存储在{@link #negotiatedSupportedGroup}字段中。
	 * negotiatedServerCertificateType，negotiatedClientCertificateType 和negotiatedSupportedGroup字段被设置
	 * 为对应于所选择的密钥组的值。
	 *
	 * SSL_NULL_WITH_NULL_NULL密码套件从不 被作为授权协商
	 * <a href="http://tools.ietf.org/html/rfc5246#appendix-A.5">RFC 5246 Appendix A.5</a>
	 *
	 * 使用{@link DTLSSession #setCipherSuite（CipherSuite）}方法在要协商的会话上设置选定的密钥套件。
	 */
	private void negotiateCipherSuite(final ClientHello clientHello, final HelloExtensions serverHelloExtensions) throws HandshakeException {

		SupportedGroup group = negotiateNamedCurve(clientHello);

		for (CipherSuite cipherSuite : clientHello.getCipherSuites()) {
			// NEVER negotiate NULL cipher suite
			if (cipherSuite != CipherSuite.TLS_NULL_WITH_NULL_NULL && supportedCipherSuites.contains(cipherSuite)) {
				if (isEligible(cipherSuite, group)) {
					negotiatedSupportedGroup = group;
					session.setCipherSuite(cipherSuite);
					LOGGER.log(Level.FINER, "Negotiated cipher suite [{0}] with peer [{1}]",
							new Object[]{cipherSuite.name(), getPeerAddress()});
					return;
				}
			}
		}
		// if none of the client's proposed cipher suites matches throw exception
		AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE, session.getPeer());
		throw new HandshakeException("Client proposed unsupported cipher suites only", alert);
	}

	private boolean isEligible(final CipherSuite cipher, final SupportedGroup group) {
		boolean result = true;
		if (cipher.isEccBased()) {
			// check for matching curve
			result &= group != null;
		}
		return result;
	}



	/**
	 * Determines the elliptic curve to use during the EC based DH key exchange.
	 * 
	 * @param clientHello
	 *            the peer's <em>CLIENT_HELLO</em> message containing its
	 *            preferred elliptic curves
	 * @return the selected curve or {@code null} if server and client have no curves in common
	 */
	private static SupportedGroup negotiateNamedCurve(ClientHello clientHello) {
		SupportedGroup result = null;
		List<SupportedGroup> preferredGroups = SupportedGroup.getPreferredGroups();
		SupportedEllipticCurvesExtension extension = clientHello.getSupportedEllipticCurvesExtension();
		if (extension == null) {
			// according to RFC 4492, section 4 (https://tools.ietf.org/html/rfc4492#section-4)
			// we are free to pick any curve in this case
			if (!preferredGroups.isEmpty()) {
				result = preferredGroups.get(0);
			}
		} else {
			for (Integer preferredGroupId : extension.getSupportedGroupIds()) {
				// use first group proposed by client contained in list of server's preferred groups
				SupportedGroup group = SupportedGroup.fromId(preferredGroupId);
				if (group != null && group.isUsable() && preferredGroups.contains(group)) {
					result = group;
					break;
				}
			}
		}
		return result;
	}


	final SupportedGroup getNegotiatedSupportedGroup() {
		return negotiatedSupportedGroup;
	}

	final ServerNames getIndicatedServerNames() {
		return indicatedServerNames;
	}

	/**
	 * @return <code>true</code> if the given message is a <em>CLIENT_HELLO</em> message
	 *            and contains the same <em>client random</em> as the <code>clientRandom</code> field.
	 */
	@Override
	protected boolean isFirstMessageReceived(final HandshakeMessage handshakeMessage) {
		if (HandshakeType.CLIENT_HELLO.equals(handshakeMessage.getMessageType())) {
			Random messageRandom = ((ClientHello) handshakeMessage).getRandom();
			return Arrays.equals(clientRandom.getRandomBytes(), messageRandom.getRandomBytes());
		} else {
			return false;
		}
	}

}
