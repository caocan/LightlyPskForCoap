/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use final for collections
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache.Predicate;

/**
 * An in-memory <code>ConnectionStore</code> with a configurable maximum capacity
 * and support for evicting stale connections based on a <em>least recently used</em> policy.
 * <p>
 * The store keeps track of the connections' last-access time automatically.
 * Every time a connection is read from or put to the store the access-time
 * is updated.
 * </p>
 * <p>
 * A connection can be successfully added to the store if any of the
 * following conditions is met:
 * </p>
 * <ul>
 * <li>The store's remaining capacity is greater than zero.</li>
 * <li>The store contains at least one <em>stale</em> connection, i.e. a
 * connection that has not been accessed for at least the store's <em>
 * connection expiration threshold</em> period. In such a case the least
 * recently accessed stale connection gets evicted from the store to make
 * place for the new connection to be added.</li>
 * </ul>
 * <p>
 * This implementation uses a <code>java.util.HashMap</code> with
 * a connection's peer address as key as its backing store.
 * In addition to that the store keeps a doubly-linked list of the
 * connections in access-time order.
 * </p>
 * <p>
 * Insertion, lookup and removal of connections is done in
 * <em>O(log n)</em>.
 * </p>
 * <p>
 * Storing and reading to/from the store is thread safe.
 * </p>
 */
public final class InMemoryConnectionStore implements ResumptionSupportingConnectionStore, SessionListener {

	private static final Logger LOG = Logger.getLogger(InMemoryConnectionStore.class.getName());
	private static final int DEFAULT_CACHE_SIZE = 150000;
	private static final long DEFAULT_EXPIRATION_THRESHOLD = 36 * 60 * 60; // 36h
	private final LeastRecentlyUsedCache<InetSocketAddress, Connection> connections;
	private final SessionCache sessionCache;

	/**
	 * Creates a store with a capacity of 500000 connections and
	 * a connection expiration threshold of 36 hours.
	 */
	public InMemoryConnectionStore() {
		this(DEFAULT_CACHE_SIZE, DEFAULT_EXPIRATION_THRESHOLD);
	}

	/**
	 * Creates a store with a capacity of 500000 connections and a connection
	 * expiration threshold of 36 hours.
	 * 
	 * @param sessionCache a second level cache to use for <em>current</em>
	 *                             connection state of established DTLS sessions.
	 */
	public InMemoryConnectionStore(final SessionCache sessionCache) {
		this(DEFAULT_CACHE_SIZE, DEFAULT_EXPIRATION_THRESHOLD, sessionCache);
	}

	/**
	 * Creates a store based on given configuration parameters.
	 * 
	 * @param capacity the maximum number of connections the store can manage
	 * @param threshold the period of time of inactivity (in seconds) after which a
	 *            connection is considered stale and can be evicted from the store if
	 *            a new connection is to be added to the store
	 */
	public InMemoryConnectionStore(final int capacity, final long threshold) {
		this(capacity, threshold, null);
	}

	/**
	 * Creates a store based on given configuration parameters.
	 * 
	 * @param capacity the maximum number of connections the store can manage
	 * @param threshold the period of time of inactivity (in seconds) after which a
	 *            connection is considered stale and can be evicted from the store if
	 *            a new connection is to be added to the store
	 * @param sessionCache a second level cache to use for <em>current</em>
	 *                     connection state of established DTLS sessions.
	 */

	/**
	 * 根据给定的配置参数创建一个存储库
	 *
	 * @param capacity 存储库中可以管理的最大连接数
	 * @param threshold 当一个连接被认为是旧的时候，这个参数表示一段连续的时间（单位
	 *                     是秒），在这段时间之内，旧连接可以被从存储库中替换出去，新
	 *                     连接可以被添加到存储库中
	 * @param sessionCache 用于已建立的DTLS会话的当前连接状态的二级缓存。
	 */
	public InMemoryConnectionStore(final int capacity, final long threshold, final SessionCache sessionCache) {
		// 将连接存储在LRU中，
		connections = new LeastRecentlyUsedCache<>(capacity, threshold);
		// 会建立一个二级cache，用来存储DTLS会话的当前连接状态
		this.sessionCache = sessionCache;

		if (sessionCache != null) {
			// make sure that session state for stale (evicted) connections is removed from second level cache
			// 确保从二级缓存中删除过时（逐出）连接的会话状态
			connections.addEvictionListener(new LeastRecentlyUsedCache.EvictionListener<Connection>() {

				@Override
				public void onEviction(Connection staleConnection) {
					removeSessionFromCache(staleConnection);
				}
			});
		}
		LOG.log(Level.CONFIG, "Created new InMemoryConnectionStore [capacity: {0}, connection expiration threshold: {1}s]",
				new Object[]{capacity, threshold});
	}

	/**
	 * Puts a connection to the store.
	 * <p>
	 * The connection's peer address is used as the key.
	 * <p>
	 * A connection can be successfully added to the store if any of the
	 * following conditions is met:
	 * <ul>
	 * <li>The store's remaining capacity is greater than zero.</li>
	 * <li>The store contains at least one <em>stale</em> connection, i.e. a
	 * connection that has not been accessed for at least the store's <em>
	 * connection expiration threshold</em> period. In such a case the least-
	 * recently accessed stale connection gets evicted from the store to make
	 * place for the new connection to be added.</li>
	 * </ul>
	 * 
	 * @return <code>true</code> if the connection could be added to the
	 *         store, <code>false</code> otherwise, e.g. because the store's
	 *         remaining capacity is zero and no stale connection can be evicted
	 */

	/**
	 * 将connection放入到store中
	 *
	 * connection的对等体的地址被用作键
	 *
	 * 如果满足以下任何一条条件，connection就可以被成功地添加到store中：
	 * - store的剩余容量大于0
	 * - 存储包含至少一个陈旧连接，即至少在商店的连接到期阈值时段内未被
	 * 访问的连接。在这种情况下，最近最少访问的陈旧连接从store中逐出，
	 * 以便为要添加的新连接腾出空间。
	 *
	 * @param connection the connection to store
	 * @return
	 */
	@Override
	public synchronized boolean put(final Connection connection) {

		if (connection != null) {
			return connections.put(connection.getPeerAddress(), connection);
		} else {
			return false;
		}
	}

	// 通过一个SessionId来查找对应的Connection
	@Override
	public synchronized Connection find(final SessionId id) {

		if (id == null) {
			return null;
		} else {
			// 从LRU找到id对应的connection
			Connection conFromLocalCache = findLocally(id);

			// 二级缓存为空的话，那么就返回从LRU找到的connection
			if (sessionCache == null) {

				return conFromLocalCache;

			} else {

				// make sure a stale session cannot be resumed
				// 确保一个过期会话不能被重用
				// 从SessionCache中获取一个会话
				SessionTicket ticket = sessionCache.get(id);
				if (ticket == null) {
					// either a session with the given ID has never been established (on other nodes)
					// or another node has removed the session from the cache, e.g. because it became
					// stale

					// 从未建立具有给定ID的会话（在其他节点上）或另一个节点
					// 已从缓存中移除了会话，例如，因为它变得陈旧
					if (conFromLocalCache != null) {
						// remove corresponding connection from this store
						remove(conFromLocalCache.getPeerAddress());
						// TODO: should we send a fatal alert to peer in this case?
					}

					return null;

				} else if (conFromLocalCache == null) {
					// this probably means that we are taking over the session from a failed node
					// 这可能意味着我们正在从一个失败的节点接管会话
						return new Connection(ticket);
						// connection will be put to first level cache as part of
						// the abbreviated handshake
					// 连接将作为简易版握手的一部分放到第一级缓存中
				} else {
					// resume connection found in local cache (i.e. this store)
					// 重用在本地缓存中被发现的connection
					return conFromLocalCache;
				}
			}
		}
	}

	private synchronized Connection findLocally(final SessionId id) {

		return connections.find(new Predicate<Connection>() {
			@Override
			public boolean accept(final Connection connection) {
				DTLSSession session = connection.getEstablishedSession();
				return session != null && id.equals(session.getSessionIdentifier());
			}
		});
	}

	@Override
	public synchronized void markAllAsResumptionRequired() {
		for (Iterator<Connection> iterator = connections.values(); iterator.hasNext(); ) {
			Connection c = iterator.next();
			if (c != null){
				c.setResumptionRequired(true);
			}
		}
	}

	@Override
	public synchronized int remainingCapacity() {
		return connections.remainingCapacity();
	}

	@Override
	public synchronized Connection get(final InetSocketAddress peerAddress) {
		return connections.get(peerAddress);
	}

	@Override
	public synchronized Connection remove(final InetSocketAddress peerAddress) {
		// 从LRU表和二级缓存中将对端地址对应的connection都进行删除
		Connection removedConnection = connections.remove(peerAddress);
		removeSessionFromCache(removedConnection);
		return removedConnection;
	}

	// 从cache中删除会话
	private synchronized void removeSessionFromCache(final Connection connection) {
		if (sessionCache != null && connection.hasEstablishedSession()) {
			sessionCache.remove(connection.getEstablishedSession().getSessionIdentifier());
		}
	}

	@Override
	public final synchronized void clear() {
		connections.clear();
		// TODO: does it make sense to clear the SessionCache as well?
	}

	@Override
	public void handshakeStarted(final Handshaker handshaker) throws HandshakeException {
		// nothing to do
	}

	@Override
	public void sessionEstablished(final Handshaker handshaker, final DTLSSession establishedSession) throws HandshakeException {
		if (sessionCache != null) {
			// put current connection state to second level cache
			// 将当前连接状态放入二级缓存中
			sessionCache.put(establishedSession);
		}
	}

	@Override
	public void handshakeCompleted(final InetSocketAddress peer) {
		// nothing to do
	}
}
