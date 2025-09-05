package haxe.crypto.mode;

import haxe.io.Bytes;

class GCM {
	/**
	 * Encrypts plaintext using AES-GCM
	 * @param src The plaintext data to encrypt
	 * @param iv The initialization vector (recommended 12 bytes)
	 * @param aad Additional Authenticated Data
	 * @param tagLen The authentication tag length (should be between 4 and 16 bytes)
	 * @param blockSize The cipher block size (16 for AES)
	 * @param encryptBlock Pointer for block encryption
	 * @return Combined ciphertext with authentication tag appended (ciphertext + tag)
	 */
	public static function encrypt(src:Bytes, iv:Bytes, aad:Bytes, tagLen:Int, blockSize:Int, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		if (tagLen < 4 || tagLen > 16) {
			throw "Tag length must be between 4 and 16 bytes (32-128 bits)";
		}
		if (aad == null)
			aad = Bytes.alloc(0);
		var H = Bytes.alloc(blockSize);
		encryptBlock(Bytes.alloc(blockSize), 0, H, 0);
		var J0 = calculateJ0(H, iv);
		var counter = incrementCounter(J0);
		var ciphertext = src.sub(0, src.length);
		CTR.encrypt(ciphertext, counter, blockSize, encryptBlock);
		var tag = calculateTag(H, aad, ciphertext, J0, encryptBlock);
		var result = Bytes.alloc(ciphertext.length + tagLen);
		result.blit(0, ciphertext, 0, ciphertext.length);
		result.blit(ciphertext.length, tag, 0, tagLen);

		return result;
	}

	/**
	 * Decrypts ciphertext using AES-GCM 
	 * @param ciphertext The encrypted data with authentication tag appended
	 * @param iv The initialization vector 
	 * @param aad Additional Authenticated Data 
	 * @param tagLen The authentication tag length (should be between 4 and 16 bytes)
	 * @param blockSize The cipher block size (16 for AES)
	 * @param encryptBlock Pointer for block encryption
	 * @return Decrypted plaintext
	 * @throws String if authentication fails or parameters are invalid
	 */
	public static function decrypt(ciphertextWithTag:Bytes, iv:Bytes, aad:Bytes, tagLen:Int, blockSize:Int, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		if (tagLen < 4 || tagLen > 16) {
			throw "Tag length must be between 4 and 16 bytes (32-128 bits)";
		}

		if (ciphertextWithTag.length < tagLen) {
			throw "Ciphertext too short for specified tag length";
		}

		var ciphertextLen = ciphertextWithTag.length - tagLen;
		var ciphertext = ciphertextWithTag.sub(0, ciphertextLen);
		var providedTag = ciphertextWithTag.sub(ciphertextLen, tagLen);
		var H = Bytes.alloc(blockSize);
		encryptBlock(Bytes.alloc(blockSize), 0, H, 0);
		var J0 = calculateJ0(H, iv);
		var computedTag = calculateTag(H, aad, ciphertext, J0, encryptBlock);
		var truncatedComputedTag = computedTag.sub(0, tagLen);
		if (!constantTimeCompare(truncatedComputedTag, providedTag)) {
			throw "Authentication failed";
		}

		var counter = incrementCounter(J0);
		var plaintext = ciphertext.sub(0, ciphertext.length);
		CTR.encrypt(plaintext, counter, blockSize, encryptBlock);

		return plaintext;
	}

	/**
	 * Calculates initial counter value according to NIST SP 800-38D
	 */
	static function calculateJ0(H:Bytes, iv:Bytes):Bytes {
		if (iv.length == 12) {
			var J0 = Bytes.alloc(16);
			J0.blit(0, iv, 0, 12);
			J0.set(15, 1);
			return J0;
		} else {
			var J0 = Bytes.alloc(16); // Initialize to zeros
			J0 = ghashUpdate(H, J0, iv);
			var lenBlock = Bytes.alloc(16);
			var ivBitLen = iv.length * 8;
			lenBlock.set(12, (ivBitLen >>> 24) & 0xFF);
			lenBlock.set(13, (ivBitLen >>> 16) & 0xFF);
			lenBlock.set(14, (ivBitLen >>> 8) & 0xFF);
			lenBlock.set(15, ivBitLen & 0xFF);
			J0 = ghashUpdate(H, J0, lenBlock);
			
			return J0;
		}
	}

	static function incrementCounter(counter:Bytes):Bytes {
		var result = counter.sub(0, counter.length);
		var carry = 1;
		var i = 15;
		while (carry > 0 && i >= 12) {
			var val = result.get(i) + carry;
			result.set(i, val & 0xFF);
			carry = val >>> 8;
			i--;
		}
		return result;
	}

	/**
	 * Calculates the tag using GHASH and counter encryption
	 */
	static function calculateTag(H:Bytes, aad:Bytes, ciphertext:Bytes, J0:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		var authData = ghash(H, aad, ciphertext);
		var encryptedJ0 = Bytes.alloc(16);
		encryptBlock(J0, 0, encryptedJ0, 0);
		for (i in 0...16) {
			authData.set(i, authData.get(i) ^ encryptedJ0.get(i));
		}
		return authData;
	}

	static function ghash(H:Bytes, aad:Bytes, ciphertext:Bytes):Bytes {
		var X = Bytes.alloc(16);
		if (aad.length > 0) {
			X = ghashUpdate(H, X, aad);
		}
		if (ciphertext.length > 0) {
			X = ghashUpdate(H, X, ciphertext);
		}
		var lenBlock = Bytes.alloc(16);
		var aadBitLen = aad.length * 8;
		var cipherBitLen = ciphertext.length * 8;
		lenBlock.set(4, (aadBitLen >>> 24) & 0xFF);
		lenBlock.set(5, (aadBitLen >>> 16) & 0xFF);
		lenBlock.set(6, (aadBitLen >>> 8) & 0xFF);
		lenBlock.set(7, aadBitLen & 0xFF);
		lenBlock.set(12, (cipherBitLen >>> 24) & 0xFF);
		lenBlock.set(13, (cipherBitLen >>> 16) & 0xFF);
		lenBlock.set(14, (cipherBitLen >>> 8) & 0xFF);
		lenBlock.set(15, cipherBitLen & 0xFF);
		for (j in 0...16) {
			X.set(j, X.get(j) ^ lenBlock.get(j));
		}
		X = gmult(X, H);
		
		return X;
	}

	static function ghashUpdate(H:Bytes, state:Bytes, data:Bytes):Bytes {
		var X = state.sub(0, 16); // Copy current state
		var pos = 0;
		var remaining = data.length;
		
		while (remaining > 0) {
			var block = Bytes.alloc(16);
			var bytesToCopy = remaining < 16 ? remaining : 16;
			block.blit(0, data, pos, bytesToCopy);
			for (j in 0...16) {
				X.set(j, X.get(j) ^ block.get(j));
			}
			X = gmult(X, H);
			
			pos += 16;
			remaining -= 16;
		}
		
		return X;
	}

	static function xorBytes(a:Bytes, b:Bytes):Bytes {
		var result = Bytes.alloc(a.length);
		var len = a.length;
		for (i in 0...len) {
			result.set(i, a.get(i) ^ b.get(i));
		}
		return result;
	}

	static function gmult(X:Bytes, Y:Bytes):Bytes {
		var Z = Bytes.alloc(16);
		var V = Y.sub(0, 16);

		for (i in 0...128) {
			var byteIndex = i >>> 3;
			var bitIndex = 7 - (i & 7);
			var bit = (X.get(byteIndex) >>> bitIndex) & 1;

			if (bit == 1) {
				for (j in 0...16) {
					Z.set(j, Z.get(j) ^ V.get(j));
				}
			}

			var lsb = V.get(15) & 1;

			var carry = 0;
			for (j in 0...16) {
				var b = V.get(j);
				var newCarry = (b & 1) << 7;
				V.set(j, (b >>> 1) | carry);
				carry = newCarry;
			}

			if (lsb == 1) {
				V.set(0, V.get(0) ^ 0xE1);
			}
		}

		return Z;
	}

	static function constantTimeCompare(a:Bytes, b:Bytes):Bool {
		if (a.length != b.length)
			return false;
		var result = 0;
		var len = a.length;
		for (i in 0...len) {
			result |= a.get(i) ^ b.get(i);
		}
		return result == 0;
	}
}