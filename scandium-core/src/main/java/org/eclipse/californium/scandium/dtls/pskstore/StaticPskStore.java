package org.eclipse.californium.scandium.dtls.pskstore;

import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.eclipse.californium.scandium.util.ServerNames;

/**
 * 一个简易的在内存中的PSK密钥库
 * <p>
 * 此实现始终为所有对等体返回相同的标识/密钥，主要用于测试和评估目的。
 * <p>
 * NB Keeping keys in in-memory is not a good idea for production. Instead, keys
 * should be kept in an encrypted store.
 */
public class StaticPskStore implements PskStore {

	private final byte[] key;
	private final String fixedIdentity;

	/**
	 * 创建一个identity和一个密钥的存储库
	 * 
	 * @param identity The (single) identity to always use.
	 * @param key The (single) key for the identity.
	 */
	public StaticPskStore(final String identity, final byte[] key) {
		this.fixedIdentity = identity;
		this.key = Arrays.copyOf(key, key.length);
	}

	@Override
	public String getIdentity(final InetSocketAddress inetAddress) {
		return fixedIdentity;
	}

	@Override
	public byte[] getKey(final String identity) {
		return key;
	}

	@Override
	public byte[] getKey(final ServerNames serverNames, final String identity) {
		return key;
	}

	// 遍历密钥库，将所有的identity提出出来返回
	@Override
	public Set<String> getAllIdentity() {
		Set<String> identities = new HashSet<>();
		identities.add(fixedIdentity);
		return identities;
	}
}
