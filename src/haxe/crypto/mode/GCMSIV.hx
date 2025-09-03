package haxe.crypto.mode;

import haxe.io.Bytes;

class GCMSIV {
	public static final AES_BLOCK_SIZE = 16;
	public static final NONCE_SIZE = 12;
	static final FIELD_MASK:Int64 = Int64.make(0xe1000000, 0);

	/**
	 * Encrypts plaintext using AES-GCM-SIV authenticated encryption mode
	 * @param key The encryption key (16 bytes for AES-128 or 32 bytes for AES-256)
	 * @param nonce The nonce - must be 12 bytes
	 * @param plaintext The data to be encrypted 
	 * @param aad Additional Authenticated Data
	 * @param encryptBlock Pointer for block encryption
	 * @param initKey Pointer to initialize cipher
	 * @return Encrypted ciphertext with authentication tag appended
	 */
	public static function encrypt(key:Bytes, nonce:Bytes, plaintext:Bytes, aad:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void,
			initKey:Bytes->?Bytes->Void):Bytes {
		if (key.length != 16 && key.length != 32) {
			throw "Invalid key length";
		}
		if (nonce.length != NONCE_SIZE) {
			throw "Invalid nonce length";
		}

		var isShortKey = key.length == 16;
		var authenticationKey = deriveKey(0, 1, nonce, encryptBlock);
		var encryptionKey = deriveKey(2, (isShortKey ? 3 : 5), nonce, encryptBlock);
		var authTag = computeTag(encryptionKey, authenticationKey, nonce, plaintext, aad, encryptBlock, initKey);
		var result = Bytes.alloc(plaintext.length + AES_BLOCK_SIZE);

		if (plaintext.length > 0) {
			initKey(encryptionKey,nonce);
			var tempCtr:Bytes = plaintext.sub(0, plaintext.length);
			CTR.encrypt(tempCtr, authTag, AES_BLOCK_SIZE, encryptBlock);
			result.blit(0, tempCtr, 0, tempCtr.length);
		}

		initKey(key, nonce);

		result.blit(plaintext.length, authTag, 0, AES_BLOCK_SIZE);
		return result;
	}

	/**
	 * Decrypts ciphertext using AES-GCM-SIV authenticated encryption mode
	 * @param key The decryption key (16 bytes for AES-128 or 32 bytes for AES-256)
	 * @param nonce The nonce - must be 12 bytes
	 * @param ciphertext The encrypted data with authentication tag (minimum 16 bytes)
	 * @param aad Additional Authenticated Data
	 * @param encryptBlock Pointer for block encryption
	 * @param initKey Pointer to initialize cipher
	 * @return Decrypted plaintext if authentication succeeds, null if authentication fails
	 */
	public static function decrypt(key:Bytes, nonce:Bytes, ciphertext:Bytes, aad:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void,
			initKey:Bytes->?Bytes->Void):Bytes {
		if (key.length != 16 && key.length != 32) {
			throw "Invalid key length";
		}
		if (nonce.length != NONCE_SIZE) {
			throw "Invalid nonce length";
		}
		if (ciphertext.length < AES_BLOCK_SIZE) {
			throw "Invalid ciphertext length";
		}

		var isShortKey = key.length == 16;
		var ciphertextLength = ciphertext.length - AES_BLOCK_SIZE;

		var encryptedData = ciphertext.sub(0, ciphertextLength);
		var providedTag = ciphertext.sub(ciphertextLength, AES_BLOCK_SIZE);

		var authenticationKey = deriveKey(0, 1, nonce, encryptBlock);
		var encryptionKey = deriveKey(2, (isShortKey ? 3 : 5), nonce, encryptBlock);
		var plaintext = Bytes.alloc(ciphertextLength);

		if (ciphertextLength > 0) {
			plaintext.blit(0, encryptedData, 0, ciphertextLength);
			initKey(encryptionKey,nonce);
			CTR.encrypt(plaintext, providedTag, AES_BLOCK_SIZE, encryptBlock);
		}
		var expectedTag = computeTag(encryptionKey, authenticationKey, nonce, plaintext, aad, encryptBlock, initKey);
		initKey(key, nonce);
		if (!secureCompare(providedTag, expectedTag)) {
			return null;
		}

		return plaintext;
	}

	static function deriveKey(startCounter:Int, endCounter:Int, nonce:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		var counterBlock = Bytes.alloc(AES_BLOCK_SIZE);
		counterBlock.blit(counterBlock.length - nonce.length, nonce, 0, nonce.length);

		var derivedKeyLength = (endCounter - startCounter + 1) << 3;
		var derivedKey = Bytes.alloc(derivedKeyLength);
		var tempBlock = Bytes.alloc(AES_BLOCK_SIZE);

		for (idx in startCounter...(endCounter + 1)) {
			writeInt(idx, counterBlock, 0);
			encryptBlock(counterBlock, 0, tempBlock, 0);
			var keyPosition = (idx - startCounter) << 3;
			derivedKey.blit(keyPosition, tempBlock, 0, 8);
		}
		return derivedKey;
	}

	static function computeTag(encryptionKey:Bytes, authenticationKey:Bytes, nonce:Bytes, plaintext:Bytes, aad:Bytes,
			encryptBlock:Bytes->Int->Bytes->Int->Void, initKey:Bytes->?Bytes->Void):Bytes {
		var fieldElement0:Int64;
		var fieldElement1:Int64;
		var accumulator0 = Int64.make(0, 0);
		var accumulator1 = Int64.make(0, 0);

		var word3 = readInt(authenticationKey, 0);
		var word2 = readInt(authenticationKey, 4);
		var word1 = readInt(authenticationKey, 8);
		var word0 = readInt(authenticationKey, 12);
		var temp = word0;
		word0 = temp >>> 1;
		var carry = temp << 31;
		temp = word1;
		word1 = (temp >>> 1) | carry;
		carry = temp << 31;
		temp = word2;
		word2 = (temp >>> 1) | carry;
		carry = temp << 31;
		temp = word3;
		word3 = (temp >>> 1) | carry;

		var fieldReduction = (temp << 31 >> 8) & 0xe1000000;
		word0 ^= fieldReduction;
		fieldElement0 = Int64.make(word0, word1);
		fieldElement1 = Int64.make(word2, word3);

		var stateResult = processBytes(aad, fieldElement0, fieldElement1, accumulator0, accumulator1);
		accumulator0 = stateResult.accumulator0;
		accumulator1 = stateResult.accumulator1;

		stateResult = processBytes(plaintext, fieldElement0, fieldElement1, accumulator0, accumulator1);
		accumulator0 = stateResult.accumulator0;
		accumulator1 = stateResult.accumulator1;

		var lengthBlock = Bytes.alloc(AES_BLOCK_SIZE);
		writeLong(aad.length << 3, lengthBlock, 0);
		writeLong(plaintext.length << 3, lengthBlock, 8);
		stateResult = processBlock(lengthBlock, 0, fieldElement0, fieldElement1, accumulator0, accumulator1);
		accumulator0 = stateResult.accumulator0;
		accumulator1 = stateResult.accumulator1;

		var digest = Bytes.alloc(AES_BLOCK_SIZE);
		writeLong64(accumulator1, digest, 0);
		writeLong64(accumulator0, digest, 8);

		for (idx in 0...nonce.length) {
			digest.set(idx, digest.get(idx) ^ nonce.get(idx));
		}
		digest.set(AES_BLOCK_SIZE - 1, digest.get(AES_BLOCK_SIZE - 1) & 0x7F);
		var finalTag = Bytes.alloc(AES_BLOCK_SIZE);
		initKey(encryptionKey, nonce);
		encryptBlock(digest, 0, finalTag, 0);
		return finalTag;
	}

	static function processBytes(data:Bytes, fieldElement0:Int64, fieldElement1:Int64, accumulator0:Int64,
			accumulator1:Int64):{accumulator0:Int64, accumulator1:Int64} {
		var remainder = data.length & 15;
		var completeBlocks = data.length - remainder;

		var position = 0;
		while (position < completeBlocks) {
			var stateResult = processBlock(data, position, fieldElement0, fieldElement1, accumulator0, accumulator1);
			accumulator0 = stateResult.accumulator0;
			accumulator1 = stateResult.accumulator1;
			position += AES_BLOCK_SIZE;
		}

		if (remainder != 0) {
			var paddedBlock = Bytes.alloc(AES_BLOCK_SIZE);
			paddedBlock.blit(0, data, completeBlocks, remainder);
			var stateResult = processBlock(paddedBlock, 0, fieldElement0, fieldElement1, accumulator0, accumulator1);
			accumulator0 = stateResult.accumulator0;
			accumulator1 = stateResult.accumulator1;
		}

		return {accumulator0: accumulator0, accumulator1: accumulator1};
	}

	static function processBlock(data:Bytes, position:Int, fieldElement0:Int64, fieldElement1:Int64, accumulator0:Int64,
			accumulator1:Int64):{accumulator0:Int64, accumulator1:Int64} {
		var dataLow = readLong(data, position);
		var dataHigh = readLong(data, position + 8);
		var operand0 = Int64.xor(accumulator1, dataLow);
		var operand1 = Int64.xor(accumulator0, dataHigh);
		var multiplier0 = Int64.make(fieldElement0.high, fieldElement0.low);
		var multiplier1 = Int64.make(fieldElement1.high, fieldElement1.low);
		var product0 = Int64.make(0, 0);
		var product1 = Int64.make(0, 0);

		for (iteration in 0...64) {
			var selector = Int64.shr(operand1, 63);
			if (selector != 0) {
				product0 = Int64.xor(product0, multiplier0);
				product1 = Int64.xor(product1, multiplier1);
			}
			var lowBit = Int64.and(multiplier1, 1);
			var carryBit = Int64.and(multiplier0, 1);

			multiplier0 = Int64.make(multiplier0.high >>> 1, (multiplier0.low >>> 1) | ((multiplier0.high & 1) << 31));
			multiplier1 = Int64.make(multiplier1.high >>> 1, (multiplier1.low >>> 1) | ((multiplier1.high & 1) << 31));
			multiplier1 = Int64.xor(multiplier1, (Int64.shl(carryBit, 63)));
			if (lowBit != 0) {
				multiplier0 = Int64.xor(multiplier0, FIELD_MASK);
			}
			operand1 = Int64.shl(operand1, 1);
		}

		for (iteration in 64...127) {
			var selector = Int64.shr(operand0, 63);
			if (selector != 0) {
				product0 = Int64.xor(product0, multiplier0);
				product1 = Int64.xor(product1, multiplier1);
			}
			var lowBit = Int64.and(multiplier1, 1);
			var carryBit = Int64.and(multiplier0, 1);

			multiplier0 = Int64.make(multiplier0.high >>> 1, (multiplier0.low >>> 1) | ((multiplier0.high & 1) << 31));
			multiplier1 = Int64.make(multiplier1.high >>> 1, (multiplier1.low >>> 1) | ((multiplier1.high & 1) << 31));
			multiplier1 = Int64.xor(multiplier1, (Int64.shl(carryBit, 63)));

			if (lowBit != 0) {
				multiplier0 = Int64.xor(multiplier0, FIELD_MASK);
			}
			operand0 = Int64.shl(operand0, 1);
		}
		var lastSelector = Int64.shr(operand0, 63);
		if (lastSelector != 0) {
			return {accumulator0: Int64.xor(product0,
				Int64.and(multiplier0, lastSelector)), accumulator1: Int64.xor(product1, Int64.and(multiplier1, lastSelector))};
		} else {
			return {accumulator0: product0, accumulator1: product1};
		}
	}

	static inline function writeInt(value:Int, buffer:Bytes, offset:Int = 0) {
		buffer.set(offset, value & 0xFF);
		buffer.set(offset + 1, (value >> 8) & 0xFF);
		buffer.set(offset + 2, (value >> 16) & 0xFF);
		buffer.set(offset + 3, (value >> 24) & 0xFF);
	}

	static inline function writeLong(value:Int, buffer:Bytes, offset:Int) {
		var upperBits = value & 0xFFFFFFFF;
		var lowerBits = 0;

		buffer.set(offset, upperBits & 0xFF);
		buffer.set(offset + 1, (upperBits >> 8) & 0xFF);
		buffer.set(offset + 2, (upperBits >> 16) & 0xFF);
		buffer.set(offset + 3, (upperBits >> 24) & 0xFF);
		buffer.set(offset + 4, 0);
		buffer.set(offset + 5, 0);
		buffer.set(offset + 6, 0);
		buffer.set(offset + 7, 0);
	}

	static inline function writeLong64(value:Int64, buffer:Bytes, offset:Int) {
		var upperWord:Int32 = value.high;
		var lowerWord:Int32 = value.low;
		buffer.set(offset, lowerWord);
		buffer.set(offset + 1, (lowerWord >> 8) & 0xFF);
		buffer.set(offset + 2, (lowerWord >> 16) & 0xFF);
		buffer.set(offset + 3, (lowerWord >> 24) & 0xFF);
		buffer.set(offset + 4, upperWord);
		buffer.set(offset + 5, (upperWord >> 8) & 0xFF);
		buffer.set(offset + 6, (upperWord >> 16) & 0xFF);
		buffer.set(offset + 7, (upperWord >> 24) & 0xFF);
	}

	static inline function readInt(buffer:Bytes, offset:Int):Int {
		return (buffer.get(offset) & 0xFF) | ((buffer.get(offset + 1) & 0xFF) << 8) | ((buffer.get(offset + 2) & 0xFF) << 16) | (buffer.get(offset + 3) << 24);
	}

	static inline function readLong(buffer:Bytes, offset:Int):Int64 {
		var lowerWord = buffer.get(offset) & 0xFF;
		lowerWord |= (buffer.get(offset + 1) & 0xFF) << 8;
		lowerWord |= (buffer.get(offset + 2) & 0xFF) << 16;
		lowerWord |= buffer.get(offset + 3) << 24;

		var upperWord = buffer.get(offset + 4) & 0xFF;
		upperWord |= (buffer.get(offset + 5) & 0xFF) << 8;
		upperWord |= (buffer.get(offset + 6) & 0xFF) << 16;
		upperWord |= buffer.get(offset + 7) << 24;

		var result = Int64.make(upperWord, lowerWord);
		return result;
	}

	/**
	 * Performs constant-time comparison of two byte arrays to prevent timing attacks
	 */
	static inline function secureCompare(first:Bytes, second:Bytes):Bool {
		if (first.length != second.length)
			return false;
		var difference = 0;
		for (idx in 0...first.length) {
			difference |= first.get(idx) ^ second.get(idx);
		}
		return difference == 0;
	}
}