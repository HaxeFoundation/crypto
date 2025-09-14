package haxe.crypto;

import haxe.io.Bytes;

class XChaCha20Poly1305 {
	private var xchacha:XChaCha20;
	private var poly1305:Poly1305;

	public function new() {
		xchacha = new XChaCha20();
		poly1305 = new Poly1305();
	}

	/**
	 * Encrypts plaintext with  XChaCha20Poly1305 encryption.
	 * @param key 32-byte encryption key
	 * @param nonce 24-byte nonce
	 * @param plaintext Data to encrypt
	 * @param aad Optional additional authenticated data 
	 * @return Encrypted data concatenated with 16-byte authentication tag
	 * @throws String if key is not 32 bytes or nonce is not 24 bytes
	 */
	public function encrypt(key:Bytes, nonce:Bytes, plaintext:Bytes, ?aad:Bytes):Bytes {
		if (key == null || key.length != 32)
			throw "Key must be 32 bytes";
		if (nonce == null || nonce.length != 24)
			throw "Nonce must be 24 bytes";

		xchacha.init(key, nonce, 1);
		var ciphertext = xchacha.encrypt(plaintext);
		xchacha.init(key, nonce, 0);
		var poly1305Key = Bytes.alloc(64);
		poly1305Key.fill(0, 64, 0);
		var keystream = xchacha.encrypt(poly1305Key);
		var poly1305KeyFinal = Bytes.alloc(32);
		poly1305KeyFinal.blit(0, keystream, 0, 32);
		var tag = calculateTag(poly1305KeyFinal, aad, ciphertext);
		var result = Bytes.alloc(ciphertext.length + 16);
		result.blit(0, ciphertext, 0, ciphertext.length);
		result.blit(ciphertext.length, tag, 0, 16);
		return result;
	}

	/**
	 * Decrypts ciphertext with XChaCha20Poly1305 decryption.
	 * @param key 32-byte encryption key
	 * @param nonce 24-byte nonce
	 * @param ciphertextWithTag Encrypted data with 16-byte authentication tag appended
	 * @param aad Optional additional authenticated data
	 * @return Decrypted plaintext data
	 * @throws String if key is not 32 bytes, nonce is not 24 bytes, ciphertext is too short, or authentication fails
	 */
	public function decrypt(key:Bytes, nonce:Bytes, ciphertextWithTag:Bytes, ?aad:Bytes):Bytes {
		if (key == null || key.length != 32)
			throw "Key must be 32 bytes";
		if (nonce == null || nonce.length != 24)
			throw "Nonce must be 24 bytes";
		if (ciphertextWithTag.length < 16)
			throw "Ciphertext with tag must be at least 16 bytes";

		var ciphertextLen = ciphertextWithTag.length - 16;
		var ciphertext = Bytes.alloc(ciphertextLen);
		var tag = Bytes.alloc(16);
		ciphertext.blit(0, ciphertextWithTag, 0, ciphertextLen);
		tag.blit(0, ciphertextWithTag, ciphertextLen, 16);
		xchacha.init(key, nonce, 0);
		var poly1305Key = Bytes.alloc(64);
		poly1305Key.fill(0, 64, 0);
		var keystream = xchacha.encrypt(poly1305Key);
		var poly1305KeyFinal = Bytes.alloc(32);
		poly1305KeyFinal.blit(0, keystream, 0, 32);
		var expectedTag = calculateTag(poly1305KeyFinal, aad, ciphertext);
		if (!constantTimeEquals(tag, expectedTag))
			throw "Authentication failed";
		xchacha.init(key, nonce, 1);
		return xchacha.decrypt(ciphertext);
	}

	private function calculateTag(key:Bytes, aad:Bytes, ciphertext:Bytes):Bytes {
		poly1305.init(key);

		if (aad != null && aad.length > 0) {
			poly1305.update(aad, 0, aad.length);
			var aadPadding = (16 - (aad.length % 16)) % 16;
			if (aadPadding > 0) {
				var padding = Bytes.alloc(aadPadding);
				padding.fill(0, aadPadding, 0);
				poly1305.update(padding, 0, aadPadding);
			}
		}
		if (ciphertext.length > 0) {
			poly1305.update(ciphertext, 0, ciphertext.length);
			var ctPadding = (16 - (ciphertext.length % 16)) % 16;
			if (ctPadding > 0) {
				var padding = Bytes.alloc(ctPadding);
				padding.fill(0, ctPadding, 0);
				poly1305.update(padding, 0, ctPadding);
			}
		}
		var lengths = Bytes.alloc(16);
		var aadLen = aad != null ? aad.length : 0;
		writeLittleEndian64(lengths, 0, aadLen);
		writeLittleEndian64(lengths, 8, ciphertext.length);
		poly1305.update(lengths, 0, 16);
		return poly1305.finish();
	}

	private function writeLittleEndian64(bytes:Bytes, offset:Int, value:Int):Void {
		bytes.set(offset, value & 0xFF);
		bytes.set(offset + 1, (value >>> 8) & 0xFF);
		bytes.set(offset + 2, (value >>> 16) & 0xFF);
		bytes.set(offset + 3, (value >>> 24) & 0xFF);
		bytes.set(offset + 4, 0);
		bytes.set(offset + 5, 0);
		bytes.set(offset + 6, 0);
		bytes.set(offset + 7, 0);
	}

	private function constantTimeEquals(a:Bytes, b:Bytes):Bool {
		if (a.length != b.length)
			return false;
		var result = 0;
		for (i in 0...a.length) {
			result |= a.get(i) ^ b.get(i);
		}
		return result == 0;
	}
}
