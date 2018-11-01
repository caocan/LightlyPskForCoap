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
 * Julien Vermillard - Sierra Wireless
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.util.ServerNames;

/**
 * 用来存储PSK的identity的密钥库
 */
public interface PskStore {

	/**
	 * 给定一个identity，可以从identity中获取到预分配密钥
	 * <p>
	 * 密钥用于DTLS握手期间的相互身份验证。
	 * 
	 * @param identity 查找密钥的标识。
	 * @return The key or <code>null</code> if the given identity is unknown.
	 * @throws NullPointerException if identity is {@code null}.
	 */
	byte[] getKey(String identity);

	/**
	 * 从给定的identity中可以获取到预分配密钥
	 * <p>
	 * T密钥用于DTLS握手期间的相互身份验证。
	 * 
	 * @param serverNames The names of servers the client provided as part of
	 *            the <em>Server Name Indication</em> hello extension during the
	 *            DTLS handshake. The key returned for the given identity is
	 *            being looked up in the context of these server names.
	 *            客户端提供的服务器名称会包括在DTLS握手期间的 Server Name Indication，
	 *            一个hello扩展的一部分 。只有在客户端给定的服务器中找到对应的identity
	 *            的时候，才会将密钥返回
	 * @param identity The identity to look up the key for.
	 * @return The key or <code>null</code> if the given identity is unknown.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 */
	byte[] getKey(ServerNames serverNames, String identity);

	/**
	 * 获取用于与给定对等方进行基于PSK握手的identity
	 * <p>
	 * DTLS客户端使用此方法确定在与对等方进行基于PSK的DTLS
	 * 握手期间要包含在其CLIENT_KEY_EXCHANGE消息中的identity。
	 * 
	 * @param inetAddress The IP address of the peer to perform the handshake
	 *            with.
	 * @return The identity to use or <code>null</code> if no peer with the
	 *         given address is registered.
	 * @throws NullPointerException if address is {@code null}.
	 */
	String getIdentity(InetSocketAddress inetAddress);
}
