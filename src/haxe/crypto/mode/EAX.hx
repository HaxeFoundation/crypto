package haxe.crypto.mode;

import haxe.io.Bytes;

class EAX {
	private static inline var BLOCK_SIZE:Int = 16;

	/**
	 * Encrypt with AES-EAX mode
	 * @param src Source data
	 * @param key The AES key (16, 24, or 32 bytes)
	 * @param iv The nonce/IV
	 * @param encryptBlock Encryption function
	 * @param aad Array of associated data
	 * @return Ciphertext with authentication tag
	 */
	public static function encrypt(src:Bytes, key:Bytes, iv:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void, ?aad:Array<Bytes>):Bytes {
		var n = omac(0, iv, key, encryptBlock);
		var h:Bytes;
		if (aad != null && aad.length > 0) {
			var totalAadLength = 0;
			for (aadItem in aad) {
				totalAadLength += aadItem.length;
			}
			var combinedAad = Bytes.alloc(totalAadLength);
			var offset = 0;
			for (aadItem in aad) {
				combinedAad.blit(offset, aadItem, 0, aadItem.length);
				offset += aadItem.length;
			}
			h = omac(1, combinedAad, key, encryptBlock);
		} else {
			h = omac(1, Bytes.alloc(0), key, encryptBlock);
		}
		CTR.encrypt(src, n, BLOCK_SIZE, encryptBlock);
		var c = omac(2, src, key, encryptBlock);
		var tag = Bytes.alloc(BLOCK_SIZE);
		for (i in 0...BLOCK_SIZE) {
			tag.set(i, n.get(i) ^ h.get(i) ^ c.get(i));
		}
		var result = Bytes.alloc(src.length + BLOCK_SIZE);
		result.blit(0, src, 0, src.length);
		result.blit(src.length, tag, 0, BLOCK_SIZE);
		return result;
	}

	/**
	 * Decrypt with AES-EAX mode
	 * @param src Encrypted data (ciphertext-tag)
	 * @param key The AES key (16, 24, or 32 bytes)
	 * @param iv The nonce/IV 
	 * @param encryptBlock Encryption function
	 * @param aad Array of associated data
	 * @return Decrypted data or null if fails
	 */
	public static function decrypt(src:Bytes, key:Bytes, iv:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void, ?aad:Array<Bytes>):Bytes {
		if (src.length < BLOCK_SIZE) {
			return null;
		}
		var ciphertextLen = src.length - BLOCK_SIZE;
		var ciphertext = src.sub(0, ciphertextLen);
		var receivedTag = src.sub(ciphertextLen, BLOCK_SIZE);
		var n = omac(0, iv, key, encryptBlock);
		var h:Bytes;
		if (aad != null && aad.length > 0) {
			var totalAadLength = 0;
			for (aadItem in aad) {
				totalAadLength += aadItem.length;
			}

			var combinedAad = Bytes.alloc(totalAadLength);
			var offset = 0;
			for (aadItem in aad) {
				combinedAad.blit(offset, aadItem, 0, aadItem.length);
				offset += aadItem.length;
			}
			h = omac(1, combinedAad, key, encryptBlock);
		} else {
			h = omac(1, Bytes.alloc(0), key, encryptBlock);
		}
		var c = omac(2, ciphertext, key, encryptBlock);
		var expectedTag = Bytes.alloc(BLOCK_SIZE);
		for (i in 0...BLOCK_SIZE) {
			expectedTag.set(i, n.get(i) ^ h.get(i) ^ c.get(i));
		}
		if (!constantTimeEquals(receivedTag, expectedTag)) {
			return null;
		}
		var plaintext = Bytes.alloc(ciphertext.length);
		plaintext.blit(0, ciphertext, 0, ciphertext.length);
		CTR.decrypt(plaintext, n, BLOCK_SIZE, encryptBlock);

		return plaintext;
	}

	/**
	 * OMAC  for EAX mode 
	 */
	private static function omac(t:Int, message:Bytes, key:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		var prefixedMessage = Bytes.alloc(BLOCK_SIZE + message.length);
		for (i in 0...(BLOCK_SIZE - 1)) {
			prefixedMessage.set(i, 0);
		}
		prefixedMessage.set(BLOCK_SIZE - 1, t);
		if (message.length > 0) {
			prefixedMessage.blit(BLOCK_SIZE, message, 0, message.length);
		}
		return CMAC.generate(prefixedMessage, key, BLOCK_SIZE, encryptBlock);
	}

	private static function constantTimeEquals(a:Bytes, b:Bytes):Bool {
		if (a.length != b.length) {
			return false;
		}
		var result = 0;
		for (i in 0...a.length) {
			result |= a.get(i) ^ b.get(i);
		}
		return result == 0;
	}
}
