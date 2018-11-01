/*******************************************************************************
 * Copyright (c) 2015 - 2017 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - re-factor DTLSConnectorConfig into
 *                                               an immutable, provide a "builder" for easier
 *                                               instantiation/configuration
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for anonymous client-only
 *                                               configuration
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 483559
 *    Achim Kraus (Bosch Software Innovations GmbH) - add enable address reuse
 *    Ludwig Seitz (RISE SICS) - Added support for raw public key validation
 *******************************************************************************/

package org.eclipse.californium.scandium.config;

import java.net.InetSocketAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.scandium.dtls.ServerNameResolver;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustAllRpks;
import org.eclipse.californium.scandium.dtls.rpkstore.TrustedRpkStore;

/**
 * 用于DTLSConnector的所有配置选项的容器，此类的实例是不可变的，只能通过{@link Builder}创建
 InetSocketAddress bindToAddress = new InetSocketAddress("localhost", 0); // 使用临时端口
 DtlsConnectorConfig config = new DtlsConnectorConfig.Builder(bindToAddress)
 .setPskStore(new StaticPskStore("identity", "secret".getBytes()));
 .set... // additional configuration
 .build();

 DTLSConnector connector = new DTLSConnector(config);
 connector.start();
 ...
 */
public final class DtlsConnectorConfig {

	/******************************变量以及常量定义*****************************************/
	/**
	 * 默认的最大连接数
	 */
	public static final int DEFAULT_MAX_CONNECTIONS = 150000;
	/**
	 * 默认的连接超时时间
	 */
	public static final long DEFAULT_STALE_CONNECTION_TRESHOLD = 30 * 60; // 30 minutes
	private static final String EC_ALGORITHM_NAME = "EC";

	private boolean enableReuseAddress;
	
	private InetSocketAddress address;
	private X509Certificate[] trustStore = new X509Certificate[0];

	/**
	 * 此连接器可以一次处理的最大片段长度。
	 */
	private Integer maxFragmentLengthCode = null;

	/** The initial timer value for retransmission; rfc6347, section: 4.2.4.1 */
	private int retransmissionTimeout = 1000;

	/**
	 * 取消尝试传输消息之前的最大重传次数
	 */
	private int maxRetransmissions = 4;

	/** 服务器是否要求客户端进行身份验证 */
	private boolean clientAuthenticationRequired = true;

	/** 我们是否只发原始密钥（RPK）而不是完整证书（X509） */
	private boolean sendRawKey = true;

	/** store of the PSK */
	private PskStore pskStore = null;

	/** 在RPK和X509模式下的私钥 */
	private PrivateKey privateKey = null;

	/** 在RPK和X509模式下的公钥 */
	private PublicKey publicKey = null;

	/** 在RPK和X509模式下的证书 */
	private X509Certificate[] certChain;

	/** 按照优先顺序排列的被支持的密钥套件 */
	private CipherSuite[] supportedCipherSuites;
	
	/** 默认是信任所有的RPK **/
	private TrustedRpkStore trustedRPKs = new TrustAllRpks();

	private int outboundMessageBufferSize = 100000;

	// 最大连接数设置为150000
	private int maxConnections = DEFAULT_MAX_CONNECTIONS;
	// 连接超时时间设置为30分
	private long staleConnectionThreshold = DEFAULT_STALE_CONNECTION_TRESHOLD;

	private ServerNameResolver serverNameResolver;

	// DtlsConnectorConfig的构造函数，是一个空函数
	private DtlsConnectorConfig() {
		// empty
	}

	/****************************各个变量的getter****************************************/

	/**
	 * Gets the maximum amount of message payload data that this connector can receive in a
	 * single DTLS record.
	 * <p>
	 * The code returned is either <code>null</code> or one of the following:
	 * <ul>
	 * <li>1 - 2^9 bytes</li>
	 * <li>2 - 2^10 bytes</li>
	 * <li>3 - 2^11 bytes</li>
	 * <li>4 - 2^12 bytes</li>
	 * </ul>
	 *
	 * @return the code indicating the maximum payload length
	 */
	public Integer getMaxFragmentLengthCode() {
		return maxFragmentLengthCode;
	}

	/**
	 * Gets the (initial) time to wait before a handshake flight of messages gets re-transmitted.
	 * 
	 * This timeout gets adjusted during the course of repeated re-transmission of a flight.
	 * The DTLS spec suggests an exponential back-off strategy, i.e. after each re-transmission the
	 * timeout value is doubled.
	 * 
	 * @return the (initial) time to wait in milliseconds
	 */
	public int getRetransmissionTimeout() {
		return retransmissionTimeout;
	}

	/**
	 * Gets the maximum number of times a flight of handshake messages gets re-transmitted
	 * to a peer.
	 * 
	 * @return the maximum number of re-transmissions
	 */
	public int getMaxRetransmissions() {
		return maxRetransmissions;
	}

	/**
	 * Gets the number of outbound messages that can be buffered in memory before
	 * messages are dropped.
	 * 
	 * @return the number of messages
	 */
	public int getOutboundMessageBufferSize() {
		return outboundMessageBufferSize;
	}

	/**
	 * Gets the IP address and port the connector is bound to.
	 * 
	 * @return the address
	 */
	public InetSocketAddress getAddress() {
		return address;
	}

	/**
	 * Gets the certificates forming the chain-of-trust from 
	 * a root CA down to the certificate asserting the server's identity.
	 * 
	 * @return the certificates or <code>null</code> if the connector is
	 * not supposed to support certificate based authentication
	 */
	public X509Certificate[] getCertificateChain() {
		if (certChain == null) {
			return null;
		} else {
			return Arrays.copyOf(certChain, certChain.length);
		}
	}

	/**
	 * Gets the cipher suites the connector should advertise in a DTLS
	 * handshake.
	 * 
	 * @return the supported cipher suites (ordered by preference)
	 */
	public CipherSuite[] getSupportedCipherSuites() {
		if (supportedCipherSuites == null) {
			return new CipherSuite[0];
		} else {
			return Arrays.copyOf(supportedCipherSuites, supportedCipherSuites.length);
		}
	}

	/**
	 * Gets the private key to use for proving identity to a peer
	 * during a DTLS handshake.
	 * 
	 * @return the key
	 */
	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	/**
	 * Gets the registry of <em>shared secrets</em> used for authenticating
	 * clients during a DTLS handshake.
	 * 
	 * @return the registry
	 */
	public PskStore getPskStore() {
		return pskStore;
	}

	/**
	 * Gets the resolver to use for determining the server names to include
	 * in a <em>Server Name Indication</em> extension when initiating a handshake
	 * with a peer.
	 * <p>
	 * When a DTLS handshake is initiated with a peer and the {@link ServerNameResolver#getServerNames(InetSocketAddress)}
	 * method returns a non-null value for the peer's address, the <em>CLIENT_HELLO</em> message
	 * sent to the peer will include a <em>Server Name Indication</em> extension containing the
	 * returned server names.
	 * 
	 * @return The resolver or {@code null} if no server names should be indicated to peers.
	 */
	public ServerNameResolver getServerNameResolver() {
		return serverNameResolver;
	}

	/**
	 * Gets the public key to send to peers during the DTLS handshake
	 * for authentication purposes.
	 * 
	 * @return the key
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Gets the trusted root certificates to use when verifying
	 * a peer's certificate during authentication.
	 * 
	 * @return the root certificates
	 */
	public X509Certificate[] getTrustStore() {
		return trustStore;
	}

	/**
	 * Sets whether the connector requires DTLS clients to authenticate during
	 * the handshake.
	 * 
	 * @return <code>true</code> if clients need to authenticate
	 */
	public boolean isClientAuthenticationRequired() {
		return clientAuthenticationRequired;
	}

	/**
	 * Checks whether the connector will send a <em>raw public key</em>
	 * instead of an X.509 certificate in order to authenticate to the peer
	 * during a DTLS handshake.
	 * 
	 * Note that this property is only relevant for cipher suites using certificate
	 * based authentication.
	 * 
	 * @return <code>true</code> if <em>RawPublicKey</em> is used by the connector
	 */
	/**
	 * 检查connector是否要发送原始公钥而不是X.509证书，以便在DTLS握手期间向对等方进行
	 * 身份验证。请注意，此属性仅与使用基于证书的身份验证的密钥套件相关
	 * @return
	 */
	public boolean isSendRawKey() {
		return sendRawKey;
	}

	/**
	 * @return true, if address reuse should be enabled for the socket. 
	 */
	public boolean isAddressReuseEnabled() {
		return enableReuseAddress;
	}
	
	/**
	 * Gets the maximum number of (active) connections the connector will support.
	 * <p>
	 * Once this limit is reached, new connections will only be accepted if <em>stale</em>
	 * connections exist. A stale connection is one that hasn't been used for at least
	 * <em>staleConnectionThreshold</em> seconds.
	 * 
	 * @return The maximum number of active connections supported.
	 * @see #getStaleConnectionThreshold()
	 */
	public int getMaxConnections() {
		return maxConnections;
	}

	/**
	 * Gets the maximum number of seconds within which some records need to be exchanged
	 * over a connection before it is considered <em>stale</em>.
	 * <p>
	 * Once a connection becomes stale, it cannot be used to transfer DTLS records anymore.
	 * 
	 * @return The number of seconds.
	 * @see #getMaxConnections()
	 */
	public long getStaleConnectionThreshold() {
		return staleConnectionThreshold;
	}
	
	/**
	 * @return The trust store for raw public keys verified out-of-band for
	 *         DTLS-RPK handshakes
	 */
	public TrustedRpkStore getRpkTrustStore() {
		return trustedRPKs;
	}

	/**
	 * A helper for creating instances of <code>DtlsConnectorConfig</code>
	 * based on the builder pattern.
	 * 一个基于builder模式的辅助类，用来构造DtlsConnectorConfig的实例
	 */
	public static final class Builder {
		
		private DtlsConnectorConfig config;
		private boolean clientOnly;
		
		/**
		 * Creates a new instance for setting configuration options
		 * for a <code>DTLSConnector</code> instance.
		 * 
		 * Once all options are set, clients should use the {@link #build()}
		 * method to create an immutable <code>DtlsConfigurationConfig</code>
		 * instance which can be passed into the <code>DTLSConnector</code>
		 * constructor.
		 * 
		 * The builder is initialized to the following default values
		 * <ul>
		 * <li><em>maxFragmentLength</em>: 4096 bytes</li>
		 * <li><em>maxPayloadSize</em>: 4096 + 25 bytes (max fragment size + 25 bytes for headers)</li>
		 * <li><em>maxRetransmissions</em>: 4</li>
		 * <li><em>retransmissionTimeout</em>: 1000ms</li>
		 * <li><em>clientAuthenticationRequired</em>: <code>true</code></li>
		 * <li><em>outboundMessageBufferSize</em>: 100.000</li>
		 * <li><em>trustStore</em>: empty array</li>
		 * </ul>
		 * 
		 * Note that when keeping the default values, at least one of the {@link #setPskStore(PskStore)}
		 * or {@link #setIdentity(PrivateKey, PublicKey)} methods need to be used to 
		 * get a working configuration for a <code>DTLSConnector</code> that can be used
		 * as a client and server.
		 * 
		 * It is possible to create a configuration for a <code>DTLSConnector</code> that can operate
		 * as a client only without the need for setting an identity. However, this is possible
		 * only if the server does not require clients to authenticate, i.e. this only
		 * works with the ECDH based cipher suites. If you want to create such a <em>client-only</em>
		 * configuration, you need to use the {@link #setClientOnly()} method on the builder.
		 * 
		 * @param address the IP address and port the connector should bind to
		 * @throws IllegalArgumentException if the given addess is unresolved
		 */

		/**
		 * 创建一个用于为DTLSConnector实例设置配置选项的新的实例。
		 * 一旦所有选项被设置了，客户端应该使用build()方法来创建一个常量实例DtlsConfigurationConfig，这个实例可以被传入到
		 * DTLSConnector构造器中。构造器初始化为一下的默认值：
		 * - maxFragmentLength：4096字节
		 * - maxPayloadSize：4096 + 25个字节（最大分片大小+ 消息头的25个字节）
		 * - maxRetransmissions：4
		 * - retransmissionTimeout：1000ms
		 * - clientAuthenticationRequired：true
		 * - outboundMessageBufferSize：100.000
		 * - trustStore：空数组
		 *
		 * 需要注意的是当保持默认值的时候，至少有一个{@link #setPskStore（PskStore）}或{@link #setIdentity(PrivateKey, PublicKey)}方法
		 * 需要被用来获取一个针对于DTLSConnector的工作配置，这个DTLSConnector可以被客户端和服务端所使用。可以为DTLSConnector创建一个配置，
		 * 该配置只能作为客户端运行，而无需设置identity。但是，这只有在服务器不要求客户端进行身份验证时才有可能，即这仅适用于基于ECDH的密
		 * 码套件。如果你想创建这样的只有客户端的配置，那么你需要使用builder中的setClientOnly()方法
		 *
		 * @param address connector应该绑定的IP地址和端口
		 * @throws IllegalArgumentException 如果给定的地址无法解析
		 */
		public Builder(InetSocketAddress address) {
			if (address.isUnresolved()) {
				throw new IllegalArgumentException("Bind address must not be unresolved");
			}
			config = new DtlsConnectorConfig();
			config.address = address;
		}

		/**********************************各个变量的setter*******************************************/




		/**
		 * Indicates that the <em>DTLSConnector</em> will only be used as a
		 * DTLS client.
		 * 
		 * The {@link #build()} method will allow creation of a configuration
		 * without any identity being set under the following conditions:
		 * <ul>
		 * <li>only support for ECDH based cipher suites is configured</li>
		 * <li>this method has been invoked</li>
		 * </ul>
		 * 
		 * @return this builder for command chaining
		 */

		/**
		 * 指明了DTLSConnector只能被用为DTLS客户端
		 * {@link #build()} 方法将允许在以下条件下创建没有任何identity的配置：
		 * - 仅配置了对基于ECDH的密码套件的支持
		 * - 已调用此方法
		 *
		 * @return
		 */
		public Builder setClientOnly() {
			clientOnly = true;
			return this;
		}

		/**
		 * Enables address reuse for the socket.
		 * 
		 * @return this builder for command chaining
		 */
		public Builder setEnableAddressReuse(boolean enable) {
			config.enableReuseAddress = enable;
			return this;
		}

		/**
		 * Sets the maximum amount of payload data that can be received and processed by this connector
		 * in a single DTLS record.
		 * <p>
		 * The value of this property is used to indicate to peers the <em>Maximum Fragment Length</em>
		 * as defined in <a href="http://tools.ietf.org/html/rfc6066#section-4">RFC 6066, Section 4</a>.
		 * It is also used to determine the amount of memory that will be allocated for receiving UDP datagrams
		 * sent by peers from the network interface.
		 * </p>
		 * The code must be either <code>null</code> or one of the following:
		 * <ul>
		 * <li>1 - 2^9 bytes</li>
		 * <li>2 - 2^10 bytes</li>
		 * <li>3 - 2^11 bytes</li>
		 * <li>4 - 2^12 bytes</li>
		 * </ul>
		 * <p>
		 * If this property is set to <code>null</code>, the <code>DTLSConnector</code> will
		 * derive its value from the network interface's <em>Maximum Transmission Unit</em>.
		 * This means that it will set it to a value small enough to make sure that inbound
		 * messages fit into a UDP datagram having a size less or equal to the MTU.
		 * </p>
		 * 
		 * @param lengthCode the code indicating the maximum length or <code>null</code> to determine
		 *                   the maximum fragment length based on the network interface's MTU
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if the code is not one of {1, 2, 3, 4} 
		 */
		public Builder setMaxFragmentLengthCode(Integer lengthCode) {
			if (lengthCode != null && (lengthCode < 1 || lengthCode > 4)) {
				throw new IllegalArgumentException("Maximum fragment length code must be one of {1, 2, 3, 4}");
			} else {
				config.maxFragmentLengthCode = lengthCode;
				return this;
			}
		}

		/**
		 * Sets the number of outbound messages that can be buffered in memory before
		 * dropping messages.
		 * 
		 * @param capacity the number of messages to buffer
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if capacity &lt; 1
		 */
		public Builder setOutboundMessageBufferSize(int capacity) {
			if (capacity < 1) {
				throw new IllegalArgumentException("Outbound message buffer size must be at least 1");
			} else {
				config.outboundMessageBufferSize = capacity;
				return this;
			}
		}

		/**
		 * Sets the maximum number of times a flight of handshake messages gets re-transmitted
		 * to a peer.
		 * 
		 * @param count the maximum number of re-transmissions
		 * @return this builder for command chaining
		 */
		public Builder setMaxRetransmissions(int count) {
			if (count < 1) {
				throw new IllegalArgumentException("Maximum number of retransmissions must be greater than zero");
			} else {
				config.maxRetransmissions = count;
				return this;
			}
		}

		/**
		 * Sets whether the connector requires DTLS clients to authenticate during
		 * the handshake.
		 * 
		 * @param authRequired
		 *            <code>true</code> if clients need to authenticate
		 * @return this builder for command chaining
		 */
		public Builder setClientAuthenticationRequired(boolean authRequired) {
			config.clientAuthenticationRequired = authRequired;
			return this;
		}

		/**
		 * Sets the cipher suites supported by the connector.
		 * <p>
		 * The connector will use these cipher suites (in exactly the same order) during
		 * the DTLS handshake when negotiating a cipher suite with a peer.
		 * 
		 * @param cipherSuites the supported cipher suites in the order of preference
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if the given array is <code>null</code>, is
		 *           empty or contains {@link CipherSuite#TLS_NULL_WITH_NULL_NULL}
		 */
		public Builder setSupportedCipherSuites(CipherSuite[] cipherSuites) {
			if (cipherSuites == null || cipherSuites.length == 0) {
				throw new IllegalArgumentException("Connector must support at least one cipher suite");
			} else {
				for (CipherSuite suite : cipherSuites) {
					if (CipherSuite.TLS_NULL_WITH_NULL_NULL.equals(suite)) {
						throw new IllegalArgumentException("NULL Cipher Suite is not supported by connector");
					}
				}
				config.supportedCipherSuites = Arrays.copyOf(cipherSuites, cipherSuites.length);
				return this;
			}
		}

		/**
		 * Sets the cipher suites supported by the connector.
		 * <p>
		 * The connector will use these cipher suites (in exactly the same order) during
		 * the DTLS handshake when negotiating a cipher suite with a peer.
		 * 
		 * @param cipherSuites the names of supported cipher suites in the order of preference
		 *     (see <a href="http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4">
		 *     IANA registry</a> for a list of cipher suite names)
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if the given array contains <em>TLS_NULL_WITH_NULL_NULL</em>
		 *     or if a name from the given list is unsupported (yet)  
		 */
		public Builder setSupportedCipherSuites(String[] cipherSuites) {
			CipherSuite[] suites = new CipherSuite[cipherSuites.length];
			for (int i = 0; i < cipherSuites.length; i++) {
				if (CipherSuite.TLS_NULL_WITH_NULL_NULL.name().equals(cipherSuites[i])) {
					throw new IllegalArgumentException("NULL Cipher Suite is not supported by connector");
				} else {
					CipherSuite knownSuite = CipherSuite.getTypeByName(cipherSuites[i]);
					if (knownSuite != null) {
						suites[i] = knownSuite;
					} else {
						throw new IllegalArgumentException(
								String.format("Cipher suite [%s] is not (yet) supported", cipherSuites[i]));
					}
				}
			}
			config.supportedCipherSuites = suites;
			return this;
		}

		/**
		 * Sets the time to wait before a handshake package gets re-transmitted.
		 * 
		 * @param timeout the time in milliseconds
		 * @return this builder for command chaining
		 * @throws IllegalArgumentException if the given timeout is negative
		 */
		public Builder setRetransmissionTimeout(int timeout) {
			if (timeout < 0) {
				throw new IllegalArgumentException("Retransmission timeout must not be negative");
			} else {
				config.retransmissionTimeout = timeout;
				return this;
			}
		}

		/**
		 * Sets the key store to use for authenticating clients based
		 * on a pre-shared key.
		 * 
		 * @param pskStore
		 *            the key store
		 * @return this builder for command chaining
		 */
		public Builder setPskStore(PskStore pskStore) {
			config.pskStore = pskStore;
			return this;
		}

		/**
		 * Sets the resolver to use for determining the server names to include
		 * in a <em>Server Name Indication</em> extension when initiating a handshake
		 * with a peer.
		 * <p>
		 * When a DTLS handshake is initiated with a peer and the {@link ServerNameResolver#getServerNames(InetSocketAddress)}
		 * method returns a non-null value for the peer's address, the <em>CLIENT_HELLO</em> message
		 * sent to the peer will include a <em>Server Name Indication</em> extension containing the
		 * returned server names.
		 * 
		 * @param resolver The resolver.
		 * @return This builder for command chaining.
		 */
		public Builder setServerNameResolver(final ServerNameResolver resolver) {
			config.serverNameResolver = resolver;
			return this;
		}

		/**
		 * Sets the connector's identifying properties by means of a private
		 * and public key pair.
		 * <p>
		 * Using this method implies that the connector <em>only</em> supports
		 * <em>RawPublicKey</em> mode for authenticating to a peer.
		 * 
		 * @param privateKey the private key used for creating signatures
		 * @param publicKey the public key a peer can use to verify possession of the private key
		 * @return this builder for command chaining
		 * @throws NullPointerException if any of the given keys is <code>null</code>
		 */
		/**
		 * 通过私钥和公钥来设置connector的标识属性
		 * 使用此方法意味着connector仅支持RawPublicKey模式以对对等方进行身份验证。
		 *
		 * @param privateKey 用来创建签名的私钥
		 * @param publicKey 对等方可以使用公钥来验证私钥的拥有权
		 * @return
		 */
		public Builder setIdentity(PrivateKey privateKey, PublicKey publicKey) {
			if (privateKey == null)
				throw new NullPointerException("The private key must not be null");
			if (publicKey == null)
				throw new NullPointerException("The public key must not be null");
			config.privateKey = privateKey;
			config.publicKey = publicKey;
			config.certChain = null;
			config.sendRawKey = true;
			return this;
		}

		/**
		 * Sets the connector's identifying properties by means of a private key
		 * and a corresponding issuer certificates chain.
		 * <p>
		 * In server mode the key and certificates are used to prove the server's
		 * identity to the client. In client mode the key and certificates are used
		 * to prove the client's identity to the server.
		 * 
		 * @param privateKey
		 *            the private key used for creating signatures
		 * @param certificateChain
		 *            the chain of X.509 certificates asserting the private key subject's
		 *            identity
		 * @param preferRawPublicKeys
		 *            <code>true</code> if the connector should indicate preference for
		 *            using <em>RawPublicKey</em>s for authentication purposes in the 
		 *            handshake with a peer (instead of including the full X.509 certificate chain)
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given private key or certificate chain is <code>null</code>
		 *            or the certificate chain does not contain any certificates
		 * @throws IllegalArgumentException if the certificate chain contains a non-X.509 certificate
		 * @see #setIdentity(PrivateKey, PublicKey) for configuring <em>RawPublicKey</em>
		 *            mode only
		 */
		/**
		 * 通过私钥和相应的颁发者证书链设置connector的标识属性。
		 * 在服务器模式下，密钥和证书用于向客户端证明服务器的身份。
		 * 在客户端模式下，密钥和证书用于向服务器证明客户端的身份。
		 *
		 * @param privateKey 用于创建签名的私钥
		 * @param certificateChain X.509证书链，用来断言私钥主体的身份
		 * @param preferRawPublicKeys 如果connector应该指示在与对等方握手的时候使用RawPublicKeys进行身份验证的首选项
		 *                            （而不是包括完整的X.509证书链），则为true
		 * @return
		 */
		public Builder setIdentity(PrivateKey privateKey, Certificate[] certificateChain,
				boolean preferRawPublicKeys) {
			if (privateKey == null) {
				throw new NullPointerException("The private key must not be null");
			} else if (certificateChain == null || certificateChain.length < 1) {
				throw new NullPointerException("The certificate chain must not be null or empty");
			} else {
				config.privateKey = privateKey;
				config.certChain = toX509Certificates(certificateChain);
				config.publicKey =  config.certChain[0].getPublicKey();
				config.sendRawKey = preferRawPublicKeys;
				return this;
			}
		}

		/**
		 * Sets the root certificates the connector should use as the trust anchor when verifying
		 * a peer's identity based on an X.509 certificate chain.
		 * 
		 * @param trustedCerts the trusted root certificates
		 * @return this builder for command chaining
		 * @throws NullPointerException if the given array is <code>null</code>
		 * @throws IllegalArgumentException if the array contains a non-X.509 certificate
		 */
		/**
		 * 设置基于X.509证书链来验证对等方身份的时候, connector应用作信任锚的根证书。
		 * @param trustedCerts
		 * @return
		 */
		public Builder setTrustStore(Certificate[] trustedCerts) {
			if (trustedCerts == null) {
				throw new NullPointerException("Trust store must not be null");
			} else {
				config.trustStore = toX509Certificates(trustedCerts);
				return this;
			}
		}

		private static X509Certificate[] toX509Certificates(Certificate[] certs) {
			List<X509Certificate> result = new ArrayList<>(certs.length);
			for (Certificate cert : certs) {
				if (X509Certificate.class.isInstance(cert)) {
					result.add((X509Certificate) cert);
				} else {
					throw new IllegalArgumentException("can only process X.509 certificates");
				}
			}
			return result.toArray(new X509Certificate[certs.length]);
		}

		/**
		 * Sets the maximum number of active connections the connector should support.
		 * <p>
		 * An <em>active</em> connection is a connection that has been used within the
		 * last <em>staleConnectionThreshold</em> seconds. After that it is considered
		 * to be <em>stale</em>.
		 * <p>
		 * Once the maximum number of active connections is reached, new connections will
		 * only be accepted by the connector, if <em>stale</em> connections exist (which will
		 * be evicted one-by-one on an oldest-first basis).
		 * <p>
		 * The default value of this property is {@link DtlsConnectorConfig#DEFAULT_MAX_CONNECTIONS}.
		 * 
		 * @param maxConnections The maximum number of active connections to support.
		 * @return this builder for command chaining.
		 * @throws IllegalArgumentException if the given limit is &lt; 1.
		 * @see #setStaleConnectionThreshold(long)
		 */
		public Builder setMaxConnections(final int maxConnections) {
			if (maxConnections < 1) {
				throw new IllegalArgumentException("Max connections must be at least 1");
			} else {
				config.maxConnections = maxConnections;
				return this;
			}
		}

		/**
		 * Sets the maximum number of seconds without any data being exchanged before a connection
		 * is considered <em>stale</em>.
		 * <p>
		 * Once a connection becomes stale, it is eligible for eviction when a peer wants to establish a
		 * new connection and the connector already has <em>maxConnections</em> connections with peers
		 * established. Note that a connection is no longer considered stale, once data is being exchanged
		 * over it before it got evicted.
		 * 
		 * @param threshold The number of seconds.
		 * @return this builder for command chaining.
		 * @throws IllegalArgumentException if the given threshold is &lt; 1.
		 * @see #setMaxConnections(int)
		 */
		/**
		 * 一旦连接变得陈旧，当对等体想要建立新连接并且连接器已经与建立的对等体建立了maxConnections连接时，
		 * 它就有资格被驱逐。请注意，一旦连接数据在被驱逐之前通过它进行交换，连接就不再被认为是陈旧的。
		 * @param threshold
		 * @return
		 */

		public Builder setStaleConnectionThreshold(final long threshold) {
			if (threshold < 1) {
				throw new IllegalArgumentException("Threshold must be at least 1 second");
			} else {
				config.staleConnectionThreshold = threshold;
				return this;
			}
		}

		private boolean isConfiguredWithKeyPair() {
			return config.privateKey != null && config.publicKey != null;
		}

		/**
		 * Creates an instance of <code>DtlsConnectorConfig</code> based on the properties
		 * set on this builder.
		 * <p>
		 * If the <em>supportedCipherSuites</em> property has not been set, the
		 * builder tries to derive a reasonable set of cipher suites from the
		 * <em>pskStore</em> and <em>identity</em> properties as follows:
		 * <ol>
		 * <li>If only the <em>pskStore</em> is set: <code>{TLS_PSK_WITH_AES_128_CCM_8,
		 * TLS_PSK_WITH_AES_128_CBC_SHA256}</code></li>
		 * <li>If only the <em>identity</em> is set: <code>{TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
		 * TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}</code></li>
		 * <li>If both the <em>pskStore</em> and the <em>identity</em> are set:
		 * <code>{TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		 * TLS_PSK_WITH_AES_128_CCM_8, TLS_PSK_WITH_AES_128_CBC_SHA256}</code></li>
		 * </ol>
		 * 
		 * @return the configuration object
		 * @throws IllegalStateException if the configuration is inconsistent
		 */

		/**
		 * 根据此builder上设置的属性创建DtlsConnectorConfig的实例。
		 * 如果尚未设置supportedCipherSuites属性，那么builder将尝试从pskStore和identity属性
		 * 派生一组合理的密码套件，如下所示：
		 * 如果只设置了pskStore：{TLS_PSK_WITH_AES_128_CCM_8,TLS_PSK_WITH_AES_128_CBC_SHA256}
		 * 如果只设置了identity：{TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,TLS_PSK_WITH_AES_128_CBC_SHA256}
		 * 如果pskStore和identity都被设置了：{TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		 * TLS_PSK_WITH_AES_128_CCM_8, TLS_PSK_WITH_AES_128_CBC_SHA256}
		 * @return
		 */
		public DtlsConnectorConfig build() {
			// 如果尚未设置supportedCipherSuites属性，那么builder将尝试从pskStore和identity属性
			// 派生一组合理的密码套件
			if (config.getSupportedCipherSuites().length == 0) {
				determineCipherSuitesFromConfig();
			}

			// 如果supportedCipherSuites为空，说明既没有设置在RPK和X.509下的非对称密钥（设置identity）
			// 也没有设置PSK密钥库，所以需要抛出异常
			if (config.getSupportedCipherSuites().length == 0) {
				throw new IllegalStateException("Supported cipher suites must be set either " +
						"explicitly or implicitly by means of setting the identity or PSK store");
			}

			// 当有了被支持的密钥组以后，需要进行参数校验
			for (CipherSuite suite : config.getSupportedCipherSuites()) {
				switch (suite) {
				case TLS_PSK_WITH_AES_128_CCM_8:
				case TLS_PSK_WITH_AES_128_CBC_SHA256:
					verifyPskBasedCipherConfig();
					break;
				case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
				case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
					verifyEcBasedCipherConfig();
					break;
				default:
					break;
				}
			}

			return config;
		}

		private void verifyPskBasedCipherConfig() {
			if (config.pskStore == null) {
				throw new IllegalStateException("PSK store must be set when support for " +
						CipherSuite.TLS_PSK_WITH_AES_128_CCM_8.name() + " is configured");
			}
		}

		// 查看在PRK和X.509模式下的参数是否正确
		private void verifyEcBasedCipherConfig() {
			if (!clientOnly) {
				// 必须得设置好非对称密钥对，否则会报错
				if (config.getPrivateKey() == null || config.getPublicKey() == null) {
					throw new IllegalStateException("Identity must be set");
				} else if ( !EC_ALGORITHM_NAME.equals(config.privateKey.getAlgorithm()) ||
						!EC_ALGORITHM_NAME.equals(config.getPublicKey().getAlgorithm()) ) {
					// test if private & public key are ECDSA capable
					//  当配置了对基于ECDHE_ECDSA的密码套件的支持时，密钥必须能够支持ECDSA
					throw new IllegalStateException("Keys must be ECDSA capable when support for an " +
							"ECDHE_ECDSA based cipher suite is configured");
				}
			}
		}

		// 如果尚未设置supportedCipherSuites属性，那么builder将尝试从pskStore和identity属性
		// 派生一组合理的密码套件
		private void determineCipherSuitesFromConfig() {
			// user has not explicitly set cipher suites
			// try to guess his intentions from properties he has set
			List<CipherSuite> ciphers = new ArrayList<>();
			// 如果用户设置过非对称密钥对（RPK和X509模式下），那么添加下面两个密钥组件
			if (isConfiguredWithKeyPair()) {
				ciphers.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
				ciphers.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
			}

			// 如果用户设置过PSK密钥库，那么就设置下面两个和PSK相关的密钥组件
			if (config.pskStore != null) {
				ciphers.add(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
				ciphers.add(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256);
			}

			// 设置被支持的密钥套件列表，按照优先顺序排列
			config.supportedCipherSuites = ciphers.toArray(new CipherSuite[0]);
		}
	

		/**
		 * Sets the store for trusted raw public keys.
		 * 
		 * @param store the trust store
		 */
		public void setRpkTrustStore(TrustedRpkStore store) {
			if (store == null) {
				throw new IllegalStateException("Must provide a non-null trust store");
			}
			config.trustedRPKs = store;
		}
	}
}
