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

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
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

	private static final String SERVER_URI = "coaps://10.108.246.164:5684/secure";

	private DTLSConnector dtlsConnector;

	public SecureClient() {

			// 构造一个用于配置DtlsConnector的一个builder实例，这个实例需要绑定一个默认的地址，我们这里采用的是localhost:0
			DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder(new InetSocketAddress(0));
			// 使用builder来设置Psk密钥库。这里创建一个静态PSK存储库，对于所有的对等体，它都返回相同的identity和密钥
			// 主要用于测试。在实际生产过程中，还是简易存储在一个加密的密钥库中
			builder.setPskStore(new StaticPskStore("Client_identity", "secretPSK".getBytes()));

			//构造好DtlsConnectorConfig实例之后，可以将其用来构造一个DTLSConnector
			dtlsConnector = new DTLSConnector(builder.build());
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
