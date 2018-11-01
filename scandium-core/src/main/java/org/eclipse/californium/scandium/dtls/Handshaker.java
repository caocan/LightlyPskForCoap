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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace custom HMAC implementation
 *                                                    with standard algorithm
 *    Kai Hudalla (Bosch Software Innovations GmbH) - retrieve security parameters from cipher suite only
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for notifying a SessionListener about
 *                                                    life-cycle events
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use SortedSet for buffering fragmented messages in order
 *                                                    to avoid repetitive sorting
 *    Kai Hudalla (Bosch Software Innovations GmbH) - consolidate and fix record buffering and message re-assembly
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace local compressionMethod and cipherSuite properties
 *                                                    with corresponding properties in DTLSSession
 *    Kai Hudalla (Bosch Software Innovations GmbH) - derive max fragment length from network MTU
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use SessionListener to trigger sending of pending
 *                                                    APPLICATION messages
 *    Bosch Software Innovations GmbH - move PRF code to separate PseudoRandomFunction class
 *    Achim Kraus (Bosch Software Innovations GmbH) - use LinkedHashSet to order listeners
 *                                                    see issue #406
 *    Ludwig Seitz (RISE SICS) - Moved certificate validation here from CertificateMessage
 *    Ludwig Seitz (RISE SICS) - Added support for raw public key validation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.californium.scandium.auth.RawPublicKeyIdentity;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction;
import org.eclipse.californium.scandium.dtls.cipher.PseudoRandomFunction.Label;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustedRpkStore;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.util.ByteArrayUtils;


/**
 * A base class for the DTLS handshake protocol.
 * 
 * Contains all functionality and fields needed by all types of handshakers.
 */
public abstract class Handshaker {

	private static final String MESSAGE_DIGEST_ALGORITHM_NAME = "SHA-256";
	private static final Logger LOGGER = Logger.getLogger(Handshaker.class.getName());

	/**
	 * Indicates whether this handshaker performs the client or server part of
	 * the protocol.
	 */
	protected final boolean isClient;

	protected int state = -1;

	protected ProtocolVersion usedProtocol;
	protected Random clientRandom;
	protected Random serverRandom;

	/** The helper class to execute the ECDHE key agreement and key generation. */
	protected ECDHECryptography ecdhe;

	private byte[] masterSecret;

	private SecretKey clientWriteMACKey;
	private SecretKey serverWriteMACKey;

	private IvParameterSpec clientWriteIV;
	private IvParameterSpec serverWriteIV;

	private SecretKey clientWriteKey;
	private SecretKey serverWriteKey;

	protected final DTLSSession session;
	protected final RecordLayer recordLayer;
	/** list of trusted self-signed root certificates */
	protected final X509Certificate[] rootCertificates;

	/** The trusted raw public keys */
	protected final TrustedRpkStore rpkStore;

	/**
	 * The current sequence number (in the handshake message called message_seq)
	 * for this handshake.
	 * 握手的当前序列号（在握手消息中叫做message_seq）
	 */
	private int sequenceNumber = 0;

	/** The next expected handshake message sequence number. */
	// 下一个想要接收逇消息序列号
	private int nextReceiveSeq = 0;

	/** 一个用于接收无法立即处理记录的缓冲区 */
	protected InboundMessageBuffer inboundMessageBuffer;
	
	/** Store the fragmented messages until we are able to reassemble the handshake message. */
	protected Map<Integer, SortedSet<FragmentedHandshakeMessage>> fragmentedMessages = new HashMap<Integer, SortedSet<FragmentedHandshakeMessage>>();

	/**
	 * The message digest to compute the handshake hashes sent in the
	 * {@link Finished} messages.
	 */
	protected MessageDigest md;

	/** All the handshake messages exchanged before the CertificateVerify message. */
	protected byte[] handshakeMessages = new byte[] {};

	/** The handshaker's private key. */
	protected PrivateKey privateKey;

	/** The handshaker's public key. */
	protected PublicKey publicKey;

	/** The chain of certificates asserting this handshaker's identity */
	protected X509Certificate[] certificateChain;

	private Set<SessionListener> sessionListeners = new LinkedHashSet<>();

	private boolean changeCipherSuiteMessageExpected = false;

	// Constructor ////////////////////////////////////////////////////

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a given
	 * peer.
	 * 
	 * @param isClient indicates whether this handshaker plays the client or
	 *            server role.
	 * @param session the session this handshaker is negotiating.
	 * @param recordLayer the object to use for sending flights to the peer.
	 * @param sessionListener the listener to notify about the session's
	 *            life-cycle events.
	 * @param rootCertificates the trusted root certificates.
	 * @param maxTransmissionUnit the MTU value reported by the network
	 *            interface the record layer is bound to.
	 * @param rpkStore the store containing the trusted raw public keys.
	 * @throws IllegalStateException if the message digest required for
	 *             computing the FINISHED message hash cannot be instantiated.
	 * @throws NullPointerException if session or recordLayer is
	 *             <code>null</code>.
	 */
	protected Handshaker(boolean isClient, DTLSSession session, RecordLayer recordLayer,
			SessionListener sessionListener, X509Certificate[] rootCertificates, int maxTransmissionUnit,
			TrustedRpkStore rpkStore) {
		this(isClient, 0, session, recordLayer, sessionListener, rootCertificates, maxTransmissionUnit, rpkStore);
	}

	/**
	 * Creates a new handshaker for negotiating a DTLS session with a given
	 * peer.
	 * 
	 * @param isClient indicates whether this handshaker plays the client or
	 *            server role.
	 * @param initialMessageSeq the initial message sequence number to use and
	 *            expect in the exchange of handshake messages with the peer.
	 *            This parameter can be used to initialize the
	 *            <em>message_seq</em> and <em>receive_next_seq</em> counters to
	 *            a value larger than 0, e.g. if one or more cookie exchange
	 *            round-trips have been performed with the peer before the
	 *            handshake starts.
	 * @param session the session this handshaker is negotiating.
	 * @param recordLayer the object to use for sending flights to the peer.
	 * @param sessionListener the listener to notify about the session's
	 *            life-cycle events.
	 * @param rootCertificates the trusted root certificates.
	 * @param maxTransmissionUnit the MTU value reported by the network
	 *            interface the record layer is bound to.
	 * @param rpkStore the store containing the trusted raw public keys.
	 * @throws IllegalStateException if the message digest required for
	 *             computing the FINISHED message hash cannot be instantiated.
	 * @throws NullPointerException if session or recordLayer is
	 *             <code>null</code>.
	 * @throws IllegalArgumentException if the initial message sequence number
	 *             is negative
	 */
	protected Handshaker(boolean isClient, int initialMessageSeq, DTLSSession session, RecordLayer recordLayer,
			SessionListener sessionListener, X509Certificate[] rootCertificates, int maxTransmissionUnit,
			TrustedRpkStore rpkStore) {
		if (session == null) {
			throw new NullPointerException("DTLS Session must not be null");
		} else if (recordLayer == null) {
			throw new NullPointerException("Record layer must not be null");
		} else if (initialMessageSeq < 0) {
			throw new IllegalArgumentException("Initial message sequence number must not be negative");
		}
		this.isClient = isClient;
		this.sequenceNumber = initialMessageSeq;
		this.nextReceiveSeq = initialMessageSeq;
		this.session = session;
		this.recordLayer = recordLayer;
		addSessionListener(sessionListener);
		this.rootCertificates = rootCertificates == null ? new X509Certificate[0] : rootCertificates;
		this.session.setMaxTransmissionUnit(maxTransmissionUnit);
		this.inboundMessageBuffer = new InboundMessageBuffer();

		try {
			this.md = MessageDigest.getInstance(MESSAGE_DIGEST_ALGORITHM_NAME);
		} catch (NoSuchAlgorithmException e) {
			// this cannot happen on a Java SE 7 VM because SHA-256 is mandatory
			// to implement
			throw new IllegalStateException(String.format("Message digest algorithm %s is not available on JVM",
					MESSAGE_DIGEST_ALGORITHM_NAME));
		}
		this.rpkStore = rpkStore;
	}

	/**
	 * 一个用于缓冲inbound握手消息的队列
	 */
	class InboundMessageBuffer {

		private ChangeCipherSpecMessage changeCipherSpec = null;

		// record的排序队列，首先按照epoch排列，如果epoch相同，那么按照序列号排序
		private SortedSet<Record> queue = new TreeSet<>(new Comparator<Record>() {

			@Override
			public int compare(Record r1, Record r2) {

				if (r1.getEpoch() < r2.getEpoch()) {
					return -1;
				} else if (r1.getEpoch() > r2.getEpoch()) {
					return 1;
				} else if (r1.getSequenceNumber() < r2.getSequenceNumber()) {
					return -1;
				} else if (r1.getSequenceNumber() > r2.getSequenceNumber()) {
					return 1;
				} else {
					return 0;
				}
			}
		});

		boolean isEmpty() {
			return queue.isEmpty();
		}

		/**
		 * 使用此握手的下一个预期消息序列号获取（并从队列中删除）握手消息。
		 * 
		 * @return the message or <code>null</code> if the queue does not contain the next expected
		 *           message (yet) 
		 * @throws HandshakeException if the record's plaintext fragment could not be parsed
		 *           into a handshake message
		 * @throws GeneralSecurityException if the record's ciphertext fragment could not be decrypted 
		 */
		DTLSMessage getNextMessage() throws GeneralSecurityException, HandshakeException {

			DTLSMessage result = null;

			// 如果期望得到的是一个ChangeCipherSpec消息，那么就试图返回一个ChangeCipherSpec消息
			if (isChangeCipherSpecMessageExpected() && changeCipherSpec != null) {
				result = changeCipherSpec;
				changeCipherSpec = null;
			} else {
				// 遍历队列，如果record是在session的read epoch之内，并且序列号
				// 也等于我们期望收到的下一个消息序列号，那么就从队列中移除这个消息，
				// 并且返回这个消息
				for (Record record : queue) {
					if (record.getEpoch() == session.getReadEpoch()) {
						HandshakeMessage msg = (HandshakeMessage) record.getFragment(session.getReadState());
						if (msg.getMessageSeq() == nextReceiveSeq) {
							result = msg;
							queue.remove(record);
							break;
						}
					}
				}
			}

			return result;
		}

		/**
		 * Checks if a given record contains a message that can be processed immediately as part
		 * of the ongoing handshake.
		 * <p>
		 * This is the case if the record is from the <em>current read epoch</em> and the contained
		 * message is either a <em>CHANGE_CIPHER_SPEC</em> message or a <em>HANDSHAKE</em> message
		 * with the next expected sequence number.
		 * <p>
		 * If the record contains a message from a future epoch or having a sequence number that is
		 * not the next expected one, the record is put into a buffer for later processing when all
		 * fragments are available and/or the message's sequence number becomes the next expected one.
		 *
		 * @param record the record containing the message to check
		 * @return the contained message if the message is up for immediate processing or <code>null</code>
		 *         if the message cannot be processed immediately
		 * @throws HandshakeException if the record's plaintext fragment could not be parsed
		 *           into a message
		 * @throws GeneralSecurityException if the record's ciphertext fragment could not be de-crypted
		 */
		/**
		 * 检查给定记录是否包含可作为正在进行的握手的一部分立即处理的消息。
		 * 如果record来自当前read epoch，并且所包含的消息是CHANGE_CIPHER_SPEC消息
		 * 或具有下一个预期序列号的HANDSHAKE消息，则是这种情况。
		 * 如果record包含来自未来的read epoch，或者具有的序列号不是下一个预期的序列号，
		 * 那么先将这个record放入缓冲中，直到所有消息可用并且/或者这个消息的序列号变成了下一个预期的序列号为止
		 */
		DTLSMessage getNextMessage(Record candidate) throws GeneralSecurityException, HandshakeException {
			// 首先获取当前record的epoch
			int epoch = candidate.getEpoch();
			// epoch比会话的read epoch还小，那么丢弃掉这个record
			if (epoch < session.getReadEpoch()) {
				// discard old message
				LOGGER.log(Level.FINER,
						"Discarding message from peer [{0}] from past epoch [{1}] < current epoch [{2}]",
						new Object[]{getPeerAddress(), epoch, session.getReadEpoch()});
				return null;
			} else if (epoch == session.getReadEpoch()) {
				DTLSMessage fragment = candidate.getFragment();
				switch(fragment.getContentType()) {
				case ALERT:
					return fragment;
				case CHANGE_CIPHER_SPEC:
					// the following cases are possible:
					// 1. the CCS message is the one we currently expect
					//    -> process it immediately
					// 2. the CCS message is NOT YET expected, i.e. we are still missing one of the
					//    messages that logically need to be processed BEFORE the CCS message
					//    -> stash the CCS message and process it immediately once the missing messages
					//       have been processed
					// 3. the FINISHED message is received BEFORE the CCS message
					//    -> stash the FINISHED message (note that the FINISHED message's epoch is
					//       current read epoch + 1 and thus will have been queued by the
					//       "else" branch below
					/**
					 * 以下情况是有可能发生的:
					 * 1. CHANGE_CIPHER_SPEC消息是我们目前所期望的消息->立即处理
					 * 2. CHANGE_CIPHER_SPEC消息不是我们所预期的，也就是说，我们仍然缺少在
					 * CCS消息之前逻辑上需要处理的消息之一 -> 存储CCS消息并在处理完丢失的消息后立即处理
					 * 3. 在CCS消息之前收到FINISHED消息->存储FINISHED消息（注意FINISHED消息的epoch是当前read epoch+1，
					 * 并且会在下面的else分支里被排队）
					 */
					if (isChangeCipherSpecMessageExpected()) {
						return fragment;
					} else {
						// 存储消息，以便后面的处理
						changeCipherSpec = (ChangeCipherSpecMessage) fragment;
						return null;
					}
				case HANDSHAKE:
					HandshakeMessage handshakeMessage = (HandshakeMessage) fragment;
					int messageSeq = handshakeMessage.getMessageSeq();
					if (messageSeq == nextReceiveSeq) {
						return handshakeMessage;
					} else if (messageSeq > nextReceiveSeq) {
						LOGGER.log(Level.FINER,
								"Queued newer message from current epoch, message_seq [{0}] > next_receive_seq [{1}]",
								new Object[]{messageSeq, nextReceiveSeq});
						queue.add(candidate);
						return null;
					} else {
						LOGGER.log(Level.FINER,
								"Discarding old message, message_seq [{0}] < next_receive_seq [{1}]",
								new Object[]{messageSeq, nextReceiveSeq});
						return null;
					}
				default:
					LOGGER.log(Level.FINER, "Cannot process message of type [{0}], discarding...",
							fragment.getContentType());
					return null;
				}
			} else {
				// newer epoch, queue message record比read epoch还大，需要将这个消息排队
				queue.add(candidate);
				LOGGER.log(Level.FINER,
						"Queueing HANDSHAKE message from future epoch [{0}] > current epoch [{1}]",
						new Object[]{epoch, getSession().getReadEpoch()});
				return null;
			}
		}
	}

	/**
	 * Processes a handshake record received from a peer based on the
	 * handshake's current state.
	 * 
	 * This method only does a duplicate check as described in
	 * <a href="http://tools.ietf.org/html/rfc6347#section-4.1.2.6">
     * section 4.1.2.6 of the DTLS 1.2 spec</a> and then delegates
     * processing of the record to the {@link #doProcessMessage(DTLSMessage)}
     * method.
     * 
	 * @param record
	 *            the handshake record
	 * @throws HandshakeException if the record's plaintext fragment cannot be parsed into
	 *            a handshake message or cannot be processed properly
	 */

	/**
	 * 根据握手的当前状态处理从对等体接收的握手记录。
	 *
	 * 此方法仅执行重复检查，如DTLS 1.2规范的第4.1.2.6节中所表述的
	 * 然后将记录的处理委托给{@link #doProcessMessage（DTLSMessage）}方法。
	 * @param record
	 * @throws HandshakeException
	 */
	public final void processMessage(Record record) throws HandshakeException {
		/**
		 * DTLS 1.2规范（4.1.2.6节）建议在MAC验证之前根据记录的序列号进行重放检测，
		 * 参见http://tools.ietf.org/html/rfc6347#section-4.1.2.6
		 */
		if (!session.isDuplicate(record.getSequenceNumber())) {
			try {
				record.setSession(session);
				// 获取到下一个期望处理的DTLSMessage，也就是符合当前会话的epoch和序列号的
				DTLSMessage messageToProcess = inboundMessageBuffer.getNextMessage(record);
				while (messageToProcess != null) {
					// 检查当前得到的消息是不是一个分片，如果是一个分片的话，那么需要检查
					// 是不是可以重组为一个完整的消息，然后将重组后的完整消息返回
					if (messageToProcess instanceof FragmentedHandshakeMessage) {
						messageToProcess = handleFragmentation((FragmentedHandshakeMessage) messageToProcess);
					}

					if (messageToProcess == null) {
						// messageToProcess是一个消息分片并且一个完整消息的所有分片还没有全部收到
					} else {
						// 如果消息分片已经重组为一个完整的消息，那么需要对这个消息立即处理
						doProcessMessage(messageToProcess);
					}

					// 如果滑动窗口中有下一个期望处理的消息的话，那么将其从
					// 滑动窗口中取出，并从滑动窗口删除这个消息
					messageToProcess = inboundMessageBuffer.getNextMessage();
				}
				// 将已经收到的记录设置为已接收，那么如果再来一个重复记录的话，会对重复记录进行丢弃
				session.markRecordAsRead(record.getEpoch(), record.getSequenceNumber());
			} catch (GeneralSecurityException e) {
				LOGGER.log(Level.WARNING,
						String.format(
								"Cannot process handshake message from peer [%s] due to [%s]",
								getSession().getPeer(), e.getMessage()),
						e);
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, session.getPeer());
				throw new HandshakeException("Cannot process handshake message", alert);
			}
		} else {
			// 根据序列号检测后发现，这个记录是一个重复的握手消息
			LOGGER.log(Level.FINEST, "Discarding duplicate HANDSHAKE message received from peer [{0}]:\n{1}",
					new Object[]{record.getPeerAddress(), record});
		}
	}

	/**
	 * Does the specific processing of a message received from a peer in
	 * the course of an ongoing handshake.
	 * 
	 * This method does not do anything. Concrete handshaker implementations should
	 * override this method in order to prepare the response to the received
	 * record.
	 * 
	 * @param message the message received from the peer
	 * @throws HandshakeException if the record's plaintext fragment cannot be parsed into
	 *            a handshake message or cannot be processed properly
	 * @throws GeneralSecurityException if the record's ciphertext fragment cannot be decrypted
	 */
	protected void doProcessMessage(DTLSMessage message) throws HandshakeException, GeneralSecurityException {
	}

	/**
	 * Starts the handshake by sending the first flight to the peer.
	 * <p>
	 * The particular message to be sent depends on this peer's role in the
	 * handshake, i.e. if this end represents the client or server.
	 * </p>
	 * 
	 * @throws HandshakeException if the message to start the handshake cannot be
	 *            created and sent using the session's current security parameters.
	 */
	public abstract void startHandshake() throws HandshakeException;

	// Methods ////////////////////////////////////////////////////////

	/**
	 * First, generates the master secret from the given premaster secret and
	 * then applying the key expansion on the master secret generates a large
	 * enough key block to generate the write, MAC and IV keys. See <a
	 * href="http://tools.ietf.org/html/rfc5246#section-6.3">RFC 5246</a> for
	 * further details about the keys.
	 *
	 * @param premasterSecret
	 *            the shared premaster secret.
	 *
	 * 首先，从给定的预主密钥生成主密钥，然后在主密钥上应用key expansion生成足够
	 * 大的key block以生成write, MAC and IV keys.
	 * 有关密钥的更多详细信息，请参见
	 * <a href="http://tools.ietf.org/html/rfc5246#section-6.3"> RFC 5246 </a>。
	 */
	protected final void generateKeys(byte[] premasterSecret) {
		masterSecret = generateMasterSecret(premasterSecret);
		session.setMasterSecret(masterSecret);

		calculateKeys(masterSecret);
	}
	/**
	 * Calculates the encryption key, MAC key and IV from a given master secret.
	 * First, applies the key expansion to the master secret.
	 * 从给定的主密钥中计算出加密密钥、MAC密钥和IV
	 * 首先，将key expansion应用在主密钥上
	 * 
	 * @param masterSecret
	 *            the master secret.
	 */
	protected void calculateKeys(byte[] masterSecret) {
		// See http://tools.ietf.org/html/rfc5246#section-6.3:
		//      key_block = PRF(SecurityParameters.master_secret, "key expansion",
		//                      SecurityParameters.server_random + SecurityParameters.client_random);
		byte[] seed = ByteArrayUtils.concatenate(serverRandom.getRandomBytes(), clientRandom.getRandomBytes());
		byte[] data = PseudoRandomFunction.doPRF(masterSecret, Label.KEY_EXPANSION_LABEL, seed);

		/*
		 * Create keys as suggested in
		 * http://tools.ietf.org/html/rfc5246#section-6.3:
		 * client_write_MAC_key[SecurityParameters.mac_key_length]
		 * server_write_MAC_key[SecurityParameters.mac_key_length]
		 * client_write_key[SecurityParameters.enc_key_length]
		 * server_write_key[SecurityParameters.enc_key_length]
		 * client_write_IV[SecurityParameters.fixed_iv_length]
		 * server_write_IV[SecurityParameters.fixed_iv_length]
		 */

		int macKeyLength = session.getCipherSuite().getMacKeyLength();
		int encKeyLength = session.getCipherSuite().getEncKeyLength();
		int fixedIvLength = session.getCipherSuite().getFixedIvLength();

		clientWriteMACKey = new SecretKeySpec(data, 0, macKeyLength, "Mac");
		serverWriteMACKey = new SecretKeySpec(data, macKeyLength, macKeyLength, "Mac");

		clientWriteKey = new SecretKeySpec(data, 2 * macKeyLength, encKeyLength, "AES");
		serverWriteKey = new SecretKeySpec(data, (2 * macKeyLength) + encKeyLength, encKeyLength, "AES");

		clientWriteIV = new IvParameterSpec(data, (2 * macKeyLength) + (2 * encKeyLength), fixedIvLength);
		serverWriteIV = new IvParameterSpec(data, (2 * macKeyLength) + (2 * encKeyLength) + fixedIvLength, fixedIvLength);

	}

	/**
	 * Generates the master secret from a given shared premaster secret as
	 * described in <a href="http://tools.ietf.org/html/rfc5246#section-8.1">RFC
	 * 5246</a>.
	 * 
	 * <pre>
	 * master_secret = PRF(pre_master_secret, "master secret",
	 * 	ClientHello.random + ServerHello.random) [0..47]
	 * </pre>
	 * 
	 * @param premasterSecret
	 *            the shared premaster secret.
	 * @return the master secret.
	 */
	private byte[] generateMasterSecret(byte[] premasterSecret) {
		byte[] randomSeed = ByteArrayUtils.concatenate(clientRandom.getRandomBytes(), serverRandom.getRandomBytes());
		return PseudoRandomFunction.doPRF(premasterSecret, Label.MASTER_SECRET_LABEL, randomSeed);
	}

	/**
	 * See <a href="http://tools.ietf.org/html/rfc4279#section-2">RFC 4279</a>:
	 * The premaster secret is formed as follows: if the PSK is N octets long,
	 * concatenate a uint16 with the value N, N zero octets, a second uint16
	 * with the value N, and the PSK itself.
	 * 
	 * @param psk
	 *            the preshared key as byte array.
	 * @return the premaster secret.
	 */
	protected final byte[] generatePremasterSecretFromPSK(byte[] psk) {
		/*
		 * What we are building is the following with length fields in between:
		 * struct { opaque other_secret<0..2^16-1>; opaque psk<0..2^16-1>; };
		 */
		int length = psk.length;

		byte[] lengthField = new byte[2];
		lengthField[0] = (byte) (length >> 8);
		lengthField[1] = (byte) (length);

		byte[] zero = ByteArrayUtils.padArray(new byte[0], (byte) 0x00, length);

		byte[] premasterSecret = ByteArrayUtils.concatenate(lengthField, ByteArrayUtils.concatenate(zero, ByteArrayUtils.concatenate(lengthField, psk)));

		return premasterSecret;
	}

	protected final void setCurrentReadState() {
		DTLSConnectionState connectionState;
		if (isClient) {
			connectionState = new DTLSConnectionState(session.getCipherSuite(), session.getCompressionMethod(), serverWriteKey, serverWriteIV, serverWriteMACKey);
		} else {
			connectionState = new DTLSConnectionState(session.getCipherSuite(), session.getCompressionMethod(), clientWriteKey, clientWriteIV, clientWriteMACKey);
		}
		session.setReadState(connectionState);
	}

	protected final void setCurrentWriteState() {
		// DTLSConnectionState是一组算法和相应的安全参数，它们一起表示TLS连接的当前读取或写入状态。
		// 这些算法的参数是已知的：MAC密钥和用于读取和写入方向的连接的批量加密密钥。
		// 这个类是不可变的，因此仅适用于反应那些已经协商/建立的当前read或write状态的属性
		DTLSConnectionState connectionState;
		if (isClient) {
			connectionState = new DTLSConnectionState(session.getCipherSuite(), session.getCompressionMethod(), clientWriteKey, clientWriteIV, clientWriteMACKey);
		} else {
			connectionState = new DTLSConnectionState(session.getCipherSuite(), session.getCompressionMethod(), serverWriteKey, serverWriteIV, serverWriteMACKey);
		}
		session.setWriteState(connectionState);
	}

	/**
	 * 将DTLS消息片段包装到（可能是多个）DTLS记录中。
	 * 
	 * 设置记录的epoch，序列号并处理握手消息的碎片。
	 * 
	 * @param fragment
	 *            the message fragment
	 * @return the records containing the message fragment, ready to be sent to the
	 *            peer
	 * @throws HandshakeException if the message could not be encrypted using the session's
	 *            current security parameters
	 */
	protected final List<Record> wrapMessage(DTLSMessage fragment) throws HandshakeException {

		try {
			switch(fragment.getContentType()) {
			case HANDSHAKE:
				return wrapHandshakeMessage((HandshakeMessage) fragment);
			default:
				// other message types should not be prone to fragmentation
				// since they are only a few bytes in length
				List<Record> records = new ArrayList<Record>();
				records.add(new Record(fragment.getContentType(), session.getWriteEpoch(), session.getSequenceNumber(),
						fragment, session));
				return records;
			}
		} catch (GeneralSecurityException e) {
			throw new HandshakeException(
					"Cannot create record",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.INTERNAL_ERROR, session.getPeer()));
		}
	}

	private List<Record> wrapHandshakeMessage(HandshakeMessage handshakeMessage) throws GeneralSecurityException {
		setSequenceNumber(handshakeMessage);
		List<Record> result = new ArrayList<>();
		byte[] messageBytes = handshakeMessage.fragmentToByteArray();

		if (messageBytes.length <= session.getMaxFragmentLength()) {
			result.add(new Record(ContentType.HANDSHAKE, session.getWriteEpoch(), session.getSequenceNumber(), handshakeMessage, session));
		} else {
			// message needs to be fragmented
			LOGGER.log(
					Level.FINER,
					"Splitting up {0} message for [{1}] into multiple fragments of max {2} bytes",
					new Object[]{handshakeMessage.getMessageType(), handshakeMessage.getPeer(), session.getMaxFragmentLength()});
			// create N handshake messages, all with the
			// same message_seq value as the original handshake message
			int messageSeq = handshakeMessage.getMessageSeq();
			int numFragments = (messageBytes.length / session.getMaxFragmentLength()) + 1;
			int offset = 0;
			for (int i = 0; i < numFragments; i++) {
				int fragmentLength = session.getMaxFragmentLength();
				if (offset + fragmentLength > messageBytes.length) {
					// the last fragment is normally shorter than the maximal size
					fragmentLength = messageBytes.length - offset;
				}
				byte[] fragmentBytes = new byte[fragmentLength];
				System.arraycopy(messageBytes, offset, fragmentBytes, 0, fragmentLength);

				FragmentedHandshakeMessage fragmentedMessage =
						new FragmentedHandshakeMessage(
								fragmentBytes,
								handshakeMessage.getMessageType(),
								offset,
								messageBytes.length,
								session.getPeer());

				// all fragments have the same message_seq
				fragmentedMessage.setMessageSeq(messageSeq);
				offset += fragmentBytes.length;

				result.add(new Record(ContentType.HANDSHAKE, session.getWriteEpoch(), session.getSequenceNumber(), fragmentedMessage, session));
			}
		}
		return result;
	}

	/**
	 * Called when a fragmented handshake message is received. Checks if all
	 * fragments already here to reassemble the handshake message and if so,
	 * returns the whole handshake message.
	 * 
	 * @param fragment
	 *            the fragmented handshake message.
	 * @return the reassembled handshake message (if all fragments are available),
	 *         <code>null</code> otherwise.
	 * @throws HandshakeException
	 *             if the reassembled fragments cannot be parsed into a valid <code>HandshakeMessage</code>
	 */
	protected final HandshakeMessage handleFragmentation(FragmentedHandshakeMessage fragment) throws HandshakeException {

		LOGGER.log(Level.FINER, "Processing {0} message fragment ...", fragment.getMessageType());
		HandshakeMessage reassembledMessage = null;
		int messageSeq = fragment.getMessageSeq();
		SortedSet<FragmentedHandshakeMessage> existingFragments = fragmentedMessages.get(messageSeq);
		if (existingFragments == null) {
			existingFragments = new TreeSet<FragmentedHandshakeMessage>(new Comparator<FragmentedHandshakeMessage>() {

				// @Override
				public int compare(FragmentedHandshakeMessage o1, FragmentedHandshakeMessage o2) {
					if (o1.getFragmentOffset() == o2.getFragmentOffset()) {
						return 0;
					} else if (o1.getFragmentOffset() < o2.getFragmentOffset()) {
						return -1;
					} else {
						return 1;
					}
				}
			});
			fragmentedMessages.put(messageSeq, existingFragments);
		}
		// store fragment together with other fragments of same message_seq
		existingFragments.add(fragment);
		
		reassembledMessage = reassembleFragments(messageSeq, existingFragments,
				fragment.getMessageLength(), fragment.getMessageType(), session);
		if (reassembledMessage != null) {
			LOGGER.log(Level.FINER, "Successfully re-assembled {0} message", reassembledMessage.getMessageType());
			fragmentedMessages.remove(messageSeq);
		}
		
		return reassembledMessage;
	}
	
	/**
	 * Reassembles handshake message fragments into the original message.
	 * 
	 * @param messageSeq
	 *            the fragment's message_seq
	 * @param fragments the fragments to reassemble
	 * @param totalLength
	 *            the expected total length of the reassembled fragment
	 * @param type
	 *            the type of the handshake message
	 * @param session
	 *            the {@link DTLSSession}
	 * @return the reassembled handshake message (if all fragements are available),
	 *         <code>null</code> otherwise.
	 * @throws HandshakeException
	 *             if the reassembled fragments cannot be parsed into a valid <code>HandshakeMessage</code>
	 */
	private final HandshakeMessage reassembleFragments(
			int messageSeq,
			SortedSet<FragmentedHandshakeMessage> fragments,
			int totalLength,
			HandshakeType type,
			DTLSSession session) throws HandshakeException {

		HandshakeMessage message = null;

		byte[] reassembly = new byte[] {};
		int offset = 0;
		for (FragmentedHandshakeMessage fragmentedHandshakeMessage : fragments) {
			
			int fragmentOffset = fragmentedHandshakeMessage.getFragmentOffset();
			int fragmentLength = fragmentedHandshakeMessage.getFragmentLength();
			
			if (fragmentOffset == offset) { // eliminate duplicates
				// case: no overlap
				reassembly = ByteArrayUtils.concatenate(reassembly, fragmentedHandshakeMessage.fragmentToByteArray());
				offset = reassembly.length;
			} else if (fragmentOffset < offset && (fragmentOffset + fragmentLength) > offset) {
				// case: overlap fragment
				
				// determine the offset where the fragment adds new information for the reassembly
				int newOffset = offset - fragmentOffset;
				int newLength = fragmentLength - newOffset;
				byte[] newBytes = new byte[newLength];
				// take only the new bytes and add them
				System.arraycopy(fragmentedHandshakeMessage.fragmentToByteArray(), newOffset, newBytes, 0, newLength);	
				reassembly = ByteArrayUtils.concatenate(reassembly, newBytes);
				
				offset = reassembly.length;
			}
		}
		
		if (reassembly.length == totalLength) {
			// the reassembled fragment has the expected length
			FragmentedHandshakeMessage wholeMessage =
					new FragmentedHandshakeMessage(type, totalLength, messageSeq, 0, reassembly, getPeerAddress());
			reassembly = wholeMessage.toByteArray();
			
			KeyExchangeAlgorithm keyExchangeAlgorithm = KeyExchangeAlgorithm.NULL;
			boolean receiveRawPublicKey = false;
			if (session != null) {
				keyExchangeAlgorithm = session.getKeyExchange();
				receiveRawPublicKey = session.receiveRawPublicKey();
			}
			message = HandshakeMessage.fromByteArray(reassembly, keyExchangeAlgorithm, receiveRawPublicKey, getPeerAddress());
		}
		
		return message;
	}

	// Getters and Setters ////////////////////////////////////////////

	protected final KeyExchangeAlgorithm getKeyExchangeAlgorithm() {
		return session.getKeyExchange();
	}

	final byte[] getMasterSecret() {
		return masterSecret;
	}

	final SecretKey getClientWriteMACKey() {
		return clientWriteMACKey;
	}

	final SecretKey getServerWriteMACKey() {
		return serverWriteMACKey;
	}

	final IvParameterSpec getClientWriteIV() {
		return clientWriteIV;
	}

	final IvParameterSpec getServerWriteIV() {
		return serverWriteIV;
	}

	final SecretKey getClientWriteKey() {
		return clientWriteKey;
	}

	final SecretKey getServerWriteKey() {
		return serverWriteKey;
	}

	/**
	 * Gets the session this handshaker is used to establish.
	 * 
	 * @return the session
	 */
	public final DTLSSession getSession() {
		return session;
	}
	
	/**
	 * Gets the IP address and port of the peer this handshaker is used to
	 * negotiate a session with.
	 * 
	 * @return the peer address
	 */
	public final InetSocketAddress getPeerAddress() {
		return session.getPeer();
	}
	
	
	/**
	 * Sets the message sequence number on an outbound handshake message.
	 * 
	 * Also increases the sequence number counter afterwards.
	 * 
	 * @param message
	 *            the handshake message to set the <em>message_seq</em> on
	 */
	private void setSequenceNumber(HandshakeMessage message) {
		message.setMessageSeq(sequenceNumber);
		sequenceNumber++;
	}

	final int getNextReceiveSeq() {
		return nextReceiveSeq;
	}

	final void incrementNextReceiveSeq() {
		this.nextReceiveSeq++;
	}

	public void addSessionListener(SessionListener listener){
		if (listener != null)
			sessionListeners.add(listener);
	}
	
	public void removeSessionListener(SessionListener listener){
		if (listener != null)
			sessionListeners.remove(listener);
	}
	
	protected final void handshakeStarted() throws HandshakeException {
		for (SessionListener sessionListener : sessionListeners) {
			sessionListener.handshakeStarted(this);
		}
	}
	
	protected final void sessionEstablished() throws HandshakeException {
		for (SessionListener sessionListener : sessionListeners) {
			sessionListener.sessionEstablished(this, this.getSession());
		}
	}

	protected final void handshakeCompleted() {
		for (SessionListener sessionListener : sessionListeners) {
			sessionListener.handshakeCompleted(getPeerAddress());
		}
	}

	/**
	 * Checks whether this handshake has been initiated by the given message.
	 * 
	 * @param handshakeMessage the message to check.
	 * @return <code>true</code> if the given message has initially started this handshake.
	 */
	public final boolean hasBeenStartedByMessage(final HandshakeMessage handshakeMessage) {
		return isFirstMessageReceived(handshakeMessage);
	}

	protected boolean isFirstMessageReceived(final HandshakeMessage handshakeMessage) {
		return false;
	}

	/**
	 * Checks whether the peer's <em>CHANGE_CIPHER_SPEC</em> message is the next message
	 * expected in the ongoing handshake.
	 * 
	 * @return {@code true} if the message is expected next.
	 */
	final boolean isChangeCipherSpecMessageExpected() {
		return changeCipherSuiteMessageExpected;
	}

	/**
	 * Marks this handshaker to expect the peer's <em>CHANGE_CIPHER_SPEC</em> message next.
	 */
	protected final void expectChangeCipherSpecMessage() {
		this.changeCipherSuiteMessageExpected = true;
	}
	
	private static Set<TrustAnchor> getTrustAnchors(X509Certificate[] trustedCertificates) {
		Set<TrustAnchor> result = new HashSet<>();
		if (trustedCertificates != null) {
			for (X509Certificate cert : trustedCertificates) {
				result.add(new TrustAnchor((X509Certificate) cert, null));
			}
		}
		return result;
	}
	
	/**
	 * Validates the X.509 certificate chain provided by the the peer as part of
	 * this message, or the raw public key.
	 * 
	 * This method checks
	 * <ol>
	 * <li>that each certificate's issuer DN equals the subject DN of the next
	 * certiciate in the chain</li>
	 * <li>that each certificate is currently valid according to its validity
	 * period</li>
	 * <li>that the chain is rooted at a trusted CA</li>
	 * </ol>
	 * 
	 * OR that the raw public key is in the raw public key trust store.
	 * 
	 * @param message the certificate message
	 * 
	 * @throws HandshakeException if any of the checks fails
	 */
	public void verifyCertificate(CertificateMessage message) throws HandshakeException {
		if (message.getCertificateChain() != null) {

			Set<TrustAnchor> trustAnchors = getTrustAnchors(rootCertificates);

			try {
				PKIXParameters params = new PKIXParameters(trustAnchors);
				// TODO: implement alternative means of revocation checking
				params.setRevocationEnabled(false);

				CertPathValidator validator = CertPathValidator.getInstance("PKIX");
				validator.validate(message.getCertificateChain(), params);

			} catch (GeneralSecurityException e) {
				if (LOGGER.isLoggable(Level.FINEST)) {
					LOGGER.log(Level.FINEST, "Certificate validation failed", e);
				} else if (LOGGER.isLoggable(Level.FINE)) {
					LOGGER.log(Level.FINE, "Certificate validation failed due to {0}", e.getMessage());
				}
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE,
						session.getPeer());
				throw new HandshakeException("Certificate chain could not be validated", alert);
			}
		} else {
			RawPublicKeyIdentity rpk = new RawPublicKeyIdentity(message.getPublicKey());
			if (!rpkStore.isTrusted(rpk)) {
				LOGGER.fine("Certificate validation failed: Raw public key is not trusted");
				AlertMessage alert = new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE,
						session.getPeer());
				throw new HandshakeException("Raw public key is not trusted", alert);
			}
		}
	}
}
