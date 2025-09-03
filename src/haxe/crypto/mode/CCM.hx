package haxe.crypto.mode;

import haxe.io.Bytes;

class CCM {
	/**
	 * Encrypts plaintext using 
	 * @param src Data to encrypt
	 * @param nonce The nonce vector (between 7 and 13 bytes)
	 * @param aad Additional Authenticated Data
	 * @param tagLen Authentication tag length (must be even, between 4 and 16 bytes)
	 * @param blockSize The cipher block size ( 16 for AES)
	 * @param encryptBlock Pointer for block encryption
	 * @return Combined ciphertext with authentication tag appended (ciphertext + tag)
	 */
	public static function encrypt(src:Bytes, nonce:Bytes, aad:Bytes, tagLen:Int, blockSize:Int, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		if (nonce.length < 7 || nonce.length > 13) {
			throw "Nonce length must be between 7 and 13 bytes";
		}

		if (tagLen < 4 || tagLen > 16 || (tagLen & 1) != 0) {
			throw "Tag length must be even and between 4 and 16 bytes";
		}

		var L = 15 - nonce.length;
		var hasAAD = aad.length > 0;
		var M_prime = (tagLen - 2) >> 1;
		var L_prime = L - 1;
		var flags = (hasAAD ? 0x40 : 0) | (M_prime << 3) | L_prime;

		var B0 = Bytes.alloc(blockSize);
		B0.set(0, flags);
		B0.blit(1, nonce, 0, nonce.length);

		var msgLen = src.length;
		var pos = 15;
		while (msgLen > 0) {
			B0.set(pos, msgLen & 0xFF);
			msgLen >>>= 8;
			pos--;
		}

		var authBlocks = createAuthBlocks(B0, aad, src, blockSize);
		var tag = computeCBCMac(authBlocks, blockSize, encryptBlock);
		var ciphertext = encryptCTR(nonce, src, blockSize, encryptBlock);
		var encryptedTag = encryptTag(nonce, tag, tagLen, blockSize, encryptBlock);

		var result = Bytes.alloc(ciphertext.length + tagLen);
		result.blit(0, ciphertext, 0, ciphertext.length);
		result.blit(ciphertext.length, encryptedTag, 0, tagLen);

		return result;
	}

	/**
	 * Decrypts ciphertext using AES-CCM
	 * @param ciphertext The encrypted data with authentication tag appended
	 * @param nonce The nonce vector (between 7 and 13 bytes)
	 * @param aad Additional Authenticated Data
	 * @param tagLen Authentication tag length (must be even, between 4 and 16 bytes)
	 * @param blockSize The cipher block size ( 16 for AES)
	 * @param encryptBlock Pointer for block encryption
	 * @return Decrypted plaintext
	 * @throws String if authentication fails or invalid parameters 
	 */
	public static function decrypt(ciphertextWithTag:Bytes, nonce:Bytes, aad:Bytes, tagLen:Int, blockSize:Int,
			encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		if (nonce.length < 7 || nonce.length > 13) {
			throw "Nonce length must be between 7 and 13 bytes";
		}

		if (tagLen < 4 || tagLen > 16 || (tagLen & 1) != 0) {
			throw "Tag length must be even and between 4 and 16 bytes";
		}

		if (ciphertextWithTag.length < tagLen) {
			throw "Ciphertext too short for specified tag length";
		}

		var ciphertextLen = ciphertextWithTag.length - tagLen;
		var src = ciphertextWithTag.sub(0, ciphertextLen);
		var providedTag = ciphertextWithTag.sub(ciphertextLen, tagLen);

		var plaintext = encryptCTR(nonce, src, blockSize, encryptBlock);

		var L = 15 - nonce.length;
		var hasAAD = aad.length > 0;
		var M_prime = (tagLen - 2) >> 1;
		var L_prime = L - 1;
		var flags = (hasAAD ? 0x40 : 0) | (M_prime << 3) | L_prime;

		var B0 = Bytes.alloc(blockSize);
		B0.set(0, flags);
		B0.blit(1, nonce, 0, nonce.length);

		var msgLen = plaintext.length;
		var pos = 15;
		while (msgLen > 0) {
			B0.set(pos, msgLen & 0xFF);
			msgLen >>>= 8;
			pos--;
		}

		var authBlocks = createAuthBlocks(B0, aad, plaintext, blockSize);
		var computedTag = computeCBCMac(authBlocks, blockSize, encryptBlock);
		var encryptedComputedTag = encryptTag(nonce, computedTag, tagLen, blockSize, encryptBlock);

		if (!constantTimeCompare(encryptedComputedTag, providedTag)) {
			throw "Authentication failed";
		}

		return plaintext;
	}

	/**
	 * Creates authentication blocks for CBC-MAC computation
	 */
	static function createAuthBlocks(B0:Bytes, aad:Bytes, message:Bytes, blockSize:Int):Array<Bytes> {
		var blocks = new Array<Bytes>();
		blocks.push(B0);

		if (aad.length > 0) {
			var formattedAAD = formatAuthData(aad);
			var pos = 0;
			var remaining = formattedAAD.length;

			while (remaining > 0) {
				var block = Bytes.alloc(blockSize);
				var bytesToCopy = remaining < blockSize ? remaining : blockSize;

				block.blit(0, formattedAAD, pos, bytesToCopy);
				blocks.push(block);
				pos += blockSize;
				remaining -= blockSize;
			}
		}

		if (message.length > 0) {
			var pos = 0;
			var remaining = message.length;

			while (remaining > 0) {
				var block = Bytes.alloc(blockSize);
				var bytesToCopy = remaining < blockSize ? remaining : blockSize;

				block.blit(0, message, pos, bytesToCopy);
				blocks.push(block);
				pos += blockSize;
				remaining -= blockSize;
			}
		}

		return blocks;
	}

	/**
	 * Computes CBC-MAC authentication tag over the provided blocks
	 */
	static function computeCBCMac(blocks:Array<Bytes>, blockSize:Int, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		var X = Bytes.alloc(blockSize);
		var blocksLen = blocks.length;

		for (i in 0...blocksLen) {
			var currentBlock = blocks[i];
			for (j in 0...blockSize) {
				X.set(j, X.get(j) ^ currentBlock.get(j));
			}
			encryptBlock(X, 0, X, 0);
		}

		return X;
	}

	/**
	 * Formatted AAD with proper length encoding prefix
	 */
	static function formatAuthData(aad:Bytes):Bytes {
		if (aad.length == 0) {
			return Bytes.alloc(0);
		}

		var len = aad.length;
		var authData:Bytes;

		if (len < 0xFF00) {
			authData = Bytes.alloc(2 + len);
			authData.set(0, len >>> 8);
			authData.set(1, len & 0xFF);
			authData.blit(2, aad, 0, len);
		} else if (len <= 0xFFFFFFFF) {
			authData = Bytes.alloc(6 + len);
			authData.set(0, 0xFF);
			authData.set(1, 0xFE);
			authData.set(2, len >>> 24);
			authData.set(3, (len >>> 16) & 0xFF);
			authData.set(4, (len >>> 8) & 0xFF);
			authData.set(5, len & 0xFF);
			authData.blit(6, aad, 0, len);
		} else {
			authData = Bytes.alloc(10 + len);
			authData.set(0, 0xFF);
			authData.set(1, 0xFF);
			authData.set(2, 0);
			authData.set(3, 0);
			authData.set(4, 0);
			authData.set(5, 0);
			authData.set(6, len >>> 24);
			authData.set(7, (len >>> 16) & 0xFF);
			authData.set(8, (len >>> 8) & 0xFF);
			authData.set(9, len & 0xFF);
			authData.blit(10, aad, 0, len);
		}
		return authData;
	}

	/**
	 * Encrypts/decrypts data using CTR (Counter) mode with CCM-specific counter format
	 */
	static function encryptCTR(nonce:Bytes, message:Bytes, blockSize:Int, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		if (message.length == 0) {
			return Bytes.alloc(0);
		}

		var result = Bytes.alloc(message.length);
		var counter = Bytes.alloc(blockSize);
		var keystream = Bytes.alloc(blockSize);

		var L = 15 - nonce.length;
		var L_prime = L - 1;
		counter.set(0, L_prime);
		counter.blit(1, nonce, 0, nonce.length);

		var pos = 0;
		var counterValue = 1;
		var remaining = message.length;

		while (remaining > 0) {
			var tempCounter = counterValue;
			var counterPos = 15;
			while (tempCounter > 0) {
				counter.set(counterPos, tempCounter & 0xFF);
				tempCounter >>>= 8;
				counterPos--;
			}

			encryptBlock(counter, 0, keystream, 0);

			var bytesToProcess = remaining < blockSize ? remaining : blockSize;
			for (j in 0...bytesToProcess) {
				result.set(pos + j, message.get(pos + j) ^ keystream.get(j));
			}

			pos += blockSize;
			remaining -= blockSize;
			counterValue++;
		}

		return result;
	}

	/**
	 * Encrypts the authentication tag using counter mode with zero counter value
	 */
	static function encryptTag(nonce:Bytes, tag:Bytes, tagLen:Int, blockSize:Int, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		var counter = Bytes.alloc(blockSize);

		var L = 15 - nonce.length;
		var L_prime = L - 1;
		counter.set(0, L_prime);
		counter.blit(1, nonce, 0, nonce.length);

		var keystream = Bytes.alloc(blockSize);
		encryptBlock(counter, 0, keystream, 0);

		var encryptedTag = Bytes.alloc(tagLen);
		for (i in 0...tagLen) {
			encryptedTag.set(i, tag.get(i) ^ keystream.get(i));
		}

		return encryptedTag;
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
