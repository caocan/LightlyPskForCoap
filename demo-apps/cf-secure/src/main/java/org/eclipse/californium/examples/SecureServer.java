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
 ******************************************************************************/
package org.eclipse.californium.examples;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.logging.Level;

import org.eclipse.californium.core.CaliforniumLogger;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;


public class SecureServer {

	static {
		// 初始化日志记录工具
		CaliforniumLogger.initialize();
		CaliforniumLogger.setLevel(Level.CONFIG);
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.FINER);
	}

	// allows configuration via Californium.properties
	public static final int DTLS_PORT = NetworkConfig.getStandard().getInt(NetworkConfig.Keys.COAP_SECURE_PORT);

	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private final static String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";

	public static void main(String[] args) {

		// 创建一个Coap服务器
		CoapServer server = new CoapServer();
		// 向CoapServer中添加一个资源secure，当使用Get方法访问的时候，响应一个2.05，并且返回一句话
		server.add(new CoapResource("secure") {
			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.respond(ResponseCode.CONTENT, "hello security");
			}
		});
		// ETSI Plugtest environment
		// server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("::1", DTLS_PORT)), NetworkConfig.getStandard()));
		// server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("127.0.0.1", DTLS_PORT)), NetworkConfig.getStandard()));
		// server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("2a01:c911:0:2010::10", DTLS_PORT)), NetworkConfig.getStandard()));
		// server.addEndpoint(new CoAPEndpoint(new DTLSConnector(new InetSocketAddress("10.200.1.2", DTLS_PORT)), NetworkConfig.getStandard()));

		try {
			// 预分配密钥库，在预分配密钥库中设置一个identity和对应的密钥值
			InMemoryPskStore pskStore = new InMemoryPskStore();
			pskStore.setKey("Client_identity", "secretPSK".getBytes()); // from ETSI Plugtest test spec

			// 初始化一个信任库，信任库类型是JKS（一般默认）
			KeyStore trustStore = KeyStore.getInstance("JKS");
			// 从一个指定位置获取输入流
			InputStream inTrust = SecureServer.class.getClassLoader().getResourceAsStream(TRUST_STORE_LOCATION);
			// 加载信任库，密码设置为rootPass
			trustStore.load(inTrust, TRUST_STORE_PASSWORD.toCharArray());

			// 从信任库中导出根证书
			// 如果需要的话可以获取多个证书
			Certificate[] trustedCertificates = new Certificate[1];
			trustedCertificates[0] = trustStore.getCertificate("root");

			// 初始化一个密钥库，密钥库类型是JKS（一般默认）
			KeyStore keyStore = KeyStore.getInstance("JKS");
			// 从一个指定位置获取输入流
			InputStream in = SecureServer.class.getClassLoader().getResourceAsStream(KEY_STORE_LOCATION);
			// 加载密钥库，密码设置为endPass
			keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());

			// 创建一个Builder，将这个Builder与默认的Coaps端口5684进行绑定，也就是说coaps服务器将在5684进行监听
			DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder(new InetSocketAddress(DTLS_PORT));
			// 在config中设置支持的密钥套件
			config.setSupportedCipherSuites(new CipherSuite[]{CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
					/*CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8*/});
			// 设置一个PSK密钥库，我们这里把开始构造的那个在内存中的密钥库设置进去
			config.setPskStore(pskStore);
			// 通过别名和密码，来从密钥库中导出server对应的密钥，这个密钥将作为创建签名的私钥
			// 另外就是通过别名server来导出X.509证书链，用来断言私钥主体的身份
			// connector应该指示在与对等方握手的时候使用RawPublicKeys进行身份验证的首选项(而不是包括完整的X.509证书链)
//			config.setIdentity((PrivateKey)keyStore.getKey("server", KEY_STORE_PASSWORD.toCharArray()),
//					keyStore.getCertificateChain("server"), true);
			// 当使用X.509模式的时候，应该设置信任链的根证书
//			config.setTrustStore(trustedCertificates);

			// config.build()函数：根据此config上设置的属性创建DtlsConnectorConfig的实例
			// build()函数在构造DtlsConnectorConfig实例之前要进行参数校验，也就是如果尚未
			// 设置supportedCipherSuites属性，那么builder将尝试从pskStore和identity属性
			// 派生一组合理的密码套件

			//构造好DtlsConnectorConfig实例之后，可以将其用来构造一个DTLSConnector
			DTLSConnector connector = new DTLSConnector(config.build());

			server.addEndpoint(new CoapEndpoint(connector, NetworkConfig.getStandard()));
			server.start();

		} catch (GeneralSecurityException | IOException e) {
			System.err.println("Could not load the keystore");
			e.printStackTrace();
		}

		// add special interceptor for message traces
		for (Endpoint ep : server.getEndpoints()) {
			ep.addInterceptor(new MessageTracer());
		}

		System.out.println("Secure CoAP server powered by Scandium (Sc) is listening on port " + DTLS_PORT);
	}
}
