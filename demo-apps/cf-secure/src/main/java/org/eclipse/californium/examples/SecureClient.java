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
import java.net.URI;
import java.net.URISyntaxException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.logging.Level;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;

public class SecureClient {

	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.FINE);
	}

	private static final String TRUST_STORE_PASSWORD = "rootPass";
	private static final String KEY_STORE_PASSWORD = "endPass";
	private static final String KEY_STORE_LOCATION = "certs/keyStore.jks";
	private static final String TRUST_STORE_LOCATION = "certs/trustStore.jks";
	private static final String SERVER_URI = "coaps://localhost/secure";

	private DTLSConnector dtlsConnector;

	public SecureClient() {
//		try {
			/*// load key store
			KeyStore keyStore = KeyStore.getInstance("JKS");
			InputStream in = getClass().getClassLoader().getResourceAsStream(KEY_STORE_LOCATION);
			keyStore.load(in, KEY_STORE_PASSWORD.toCharArray());
			in.close();

			// load trust store
			KeyStore trustStore = KeyStore.getInstance("JKS");
			in = getClass().getClassLoader().getResourceAsStream(TRUST_STORE_LOCATION);
			trustStore.load(in, TRUST_STORE_PASSWORD.toCharArray());
			in.close();

			// You can load multiple certificates if needed
			Certificate[] trustedCertificates = new Certificate[1];
			trustedCertificates[0] = trustStore.getCertificate("root");*/

			// 构造一个用于配置DtlsConnector的一个builder实例，这个实例需要绑定一个默认的地址，我们这里采用的是localhost:0
			DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));
			// 使用builder来设置Psk密钥库。这里创建一个静态PSK存储库，对于所有的对等体，它都返回相同的identity和密钥
			// 主要用于测试。在实际生产过程中，还是简易存储在一个加密的密钥库中
			builder.setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));
			// 通过别名和密码，来从密钥库中导出client对应的密钥，这个密钥将作为创建签名的私钥
			// 另外就是通过别名client来导出X.509证书链，用来断言私钥主体的身份
			// true:connector应该指示在与对等方握手的时候使用RawPublicKeys进行身份验证的首选项(而不是包括完整的X.509证书链)
//			builder.setIdentity((PrivateKey)keyStore.getKey("client", KEY_STORE_PASSWORD.toCharArray()),
//					keyStore.getCertificateChain("client"), true);
			// 当使用X.509模式的时候，应该设置信任链的根证书
//			builder.setTrustStore(trustedCertificates);

			// config.build()函数：根据此config上设置的属性创建DtlsConnectorConfig的实例
			// build()函数在构造DtlsConnectorConfig实例之前要进行参数校验，也就是如果尚未
			// 设置supportedCipherSuites属性，那么builder将尝试从pskStore和identity属性
			// 派生一组合理的密码套件

			//构造好DtlsConnectorConfig实例之后，可以将其用来构造一个DTLSConnector
			dtlsConnector = new DTLSConnector(builder.build());

		/* }catch (GeneralSecurityException | IOException e) {
			System.err.println("Could not load the keystore");
			e.printStackTrace();
		}*/
	}

	public void test() {

		CoapResponse response = null;
		try {
			URI uri = new URI(SERVER_URI);

			CoapClient client = new CoapClient(uri);
			client.setEndpoint(new CoapEndpoint(dtlsConnector, NetworkConfig.getStandard()));
			response = client.get();

		} catch (URISyntaxException e) {
			System.err.println("Invalid URI: " + e.getMessage());
			System.exit(-1);
		}

		if (response != null) {

			System.out.println(response.getCode());
			System.out.println(response.getOptions());
			System.out.println(response.getResponseText());

			System.out.println("\nADVANCED\n");
			System.out.println(Utils.prettyPrint(response));

		} else {
			System.out.println("No response received.");
		}
	}

	public static void main(String[] args) throws InterruptedException {

		SecureClient client = new SecureClient();
		client.test();

		synchronized (SecureClient.class) {
			SecureClient.class.wait();
		}
	}
}
