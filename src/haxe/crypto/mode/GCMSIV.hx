package haxe.crypto.mode;

import haxe.io.Bytes;

class GCMSIV {
	public static final AES_BLOCK_SIZE = 16;
	public static final NONCE_SIZE = 12;
	static final E:Int64 = Int64.make(0xe1000000, 0);

	static var h0:Int64;
	static var h1:Int64;
	static var s0:Int64;
	static var s1:Int64;

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
		var aes128 = key.length == 16;
		var authKey = subKey(0, 1, nonce, encryptBlock);
		var encKey = subKey(2, (aes128 ? 3 : 5), nonce, encryptBlock);
		initKey(encKey);
		var tag = hash(encKey, authKey, nonce, plaintext, aad, encryptBlock);
		var output = Bytes.alloc(plaintext.length + AES_BLOCK_SIZE);
		if (plaintext.length > 0) {
			output.blit(0, plaintext, 0, plaintext.length);
			aesCTR(encKey, tag, plaintext, output, encryptBlock);
		}

		initKey(key, nonce);
		output.blit(plaintext.length, tag, 0, AES_BLOCK_SIZE);
		return output;
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
		var aes128 = key.length == 16;
		var ctLen = ciphertext.length - AES_BLOCK_SIZE;

		var c = ciphertext.sub(0, ctLen);
		var tag = ciphertext.sub(ctLen, AES_BLOCK_SIZE);

		var authKey = subKey(0, 1, nonce, encryptBlock);
		var encKey = subKey(2, (aes128 ? 3 : 5), nonce, encryptBlock);
		initKey(encKey);
		var plaintext = Bytes.alloc(ctLen);
		if (ctLen > 0) {
			plaintext.blit(0, c, 0, ctLen);
			aesCTR(encKey, tag, c, plaintext, encryptBlock);
		}

		var actualTag = hash(encKey, authKey, nonce, plaintext, aad, encryptBlock);
		initKey(key, nonce);
		if (!constantTimeCompare(tag, actualTag)) {
			return null;
		}
		return plaintext;
	}

	static function subKey(ctrStart:Int, ctrEnd:Int, nonce:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		var counter = Bytes.alloc(AES_BLOCK_SIZE);
		counter.blit(counter.length - nonce.length, nonce, 0, nonce.length);

		var keyLen = (ctrEnd - ctrStart + 1) << 3;
		var key = Bytes.alloc(keyLen);
		var block = Bytes.alloc(AES_BLOCK_SIZE);

		for (i in ctrStart...(ctrEnd + 1)) {
			putInt(i, counter, 0);
			encryptBlock(counter, 0, block, 0);
			var keyOffset = (i - ctrStart) << 3;
			key.blit(keyOffset, block, 0, 8);
		}
		return key;
	}

	static function hash(encKey:Bytes, authKey:Bytes, nonce:Bytes, plaintext:Bytes, aad:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		initPolyval(authKey);
		updatePolyval(aad);
		updatePolyval(plaintext);
		var block = Bytes.alloc(AES_BLOCK_SIZE);
		putLong(aad.length << 3, block, 0);
		putLong(plaintext.length << 3, block, 8);
		updateBlockPolyval(block, 0);
		digestPolyval(block);

		for (i in 0...nonce.length) {
			block.set(i, block.get(i) ^ nonce.get(i));
		}
		block.set(AES_BLOCK_SIZE - 1, block.get(AES_BLOCK_SIZE - 1) & 0x7F);
		var result = Bytes.alloc(AES_BLOCK_SIZE);
		encryptBlock(block, 0, result, 0);
		return result;
	}

	static function initPolyval(authKey:Bytes):Void {
		var v3 = getInt(authKey, 0);
		var v2 = getInt(authKey, 4);
		var v1 = getInt(authKey, 8);
		var v0 = getInt(authKey, 12);
		var b = v0;
		v0 = b >>> 1;
		var c = b << 31;
		b = v1;
		v1 = (b >>> 1) | c;
		c = b << 31;
		b = v2;
		v2 = (b >>> 1) | c;
		c = b << 31;
		b = v3;
		v3 = (b >>> 1) | c;

		var reduction = (b << 31 >> 8) & 0xe1000000;
		v0 ^= reduction;
		h0 = Int64.make(v0, v1);
		h1 = Int64.make(v2, v3);
		s0 = Int64.make(0, 0);
		s1 = Int64.make(0, 0);
	}

	public static inline function updatePolyval(b:Bytes) {
		var extra = b.length & 15; // % 16
		var fullBlocks = b.length - extra;

		var i = 0;
		while (i < fullBlocks) {
			updateBlockPolyval(b, i);
			i += GCMSIV.AES_BLOCK_SIZE;
		}

		if (extra != 0) {
			var block = Bytes.alloc(GCMSIV.AES_BLOCK_SIZE);
			block.blit(0, b, fullBlocks, extra);
			updateBlockPolyval(block, 0);
		}
	}

	public static function updateBlockPolyval(b:Bytes, offset:Int) {
		var block1 = getLong(b, offset);
		var block2 = getLong(b, offset + 8);
		var x0 = Int64.xor(s1, block1);
		var x1 = Int64.xor(s0, block2);
		var v0 = Int64.make(h0.high, h0.low);
		var v1 = Int64.make(h1.high, h1.low);
		var z0 = Int64.make(0, 0);
		var z1 = Int64.make(0, 0);

		for (i in 0...64) {
			var m = Int64.shr(x1, 63);
			if (m != 0) {
				z0 = Int64.xor(z0, v0);
				z1 = Int64.xor(z1, v1);
			}
			var v1SignBit = Int64.and(v1, 1); // ==0?0:-1
			var c = Int64.and(v0, 1);

			v0 = Int64.make(v0.high >>> 1, (v0.low >>> 1) | ((v0.high & 1) << 31));
			v1 = Int64.make(v1.high >>> 1, (v1.low >>> 1) | ((v1.high & 1) << 31));
			v1 = Int64.xor(v1, (Int64.shl(c, 63)));
			if (v1SignBit != 0) {
				v0 = Int64.xor(v0, E);
			}
			x1 = Int64.shl(x1, 1);
		}

		for (i in 64...127) {
			var m = Int64.shr(x0, 63);
			if (m != 0) {
				z0 = Int64.xor(z0, v0);
				z1 = Int64.xor(z1, v1);
			}
			var v1SignBit = Int64.and(v1, 1);
			var c = Int64.and(v0, 1);

			v0 = Int64.make(v0.high >>> 1, (v0.low >>> 1) | ((v0.high & 1) << 31));
			v1 = Int64.make(v1.high >>> 1, (v1.low >>> 1) | ((v1.high & 1) << 31));
			v1 = Int64.xor(v1, (Int64.shl(c, 63)));

			if (v1SignBit != 0) {
				v0 = Int64.xor(v0, E);
			}
			x0 = Int64.shl(x0, 1);
		}
		var finalM = Int64.shr(x0, 63);
		if (finalM != 0) {
			s0 = Int64.xor(z0, Int64.and(v0, finalM));
			s1 = Int64.xor(z1, Int64.and(v1, finalM));
		} else {
			s0 = z0;
			s1 = z1;
		}
	}

	public static inline function digestPolyval(d:Bytes) {
		putLong64(s1, d, 0);
		putLong64(s0, d, 8);
	}

	static inline function putLong64(n:Int64, b:Bytes, offset:Int) {
		var hi:Int32 = n.high;
		var lo:Int32 = n.low;
		b.set(offset, lo);
		b.set(offset + 1, (lo >> 8) & 0xFF);
		b.set(offset + 2, (lo >> 16) & 0xFF);
		b.set(offset + 3, (lo >> 24) & 0xFF);
		b.set(offset + 4, hi);
		b.set(offset + 5, (hi >> 8) & 0xFF);
		b.set(offset + 6, (hi >> 16) & 0xFF);
		b.set(offset + 7, (hi >> 24) & 0xFF);
	}

	static function aesCTR(key:Bytes, tag:Bytes, input:Bytes, output:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void) {
		var counter = Bytes.alloc(tag.length);
		counter.blit(0, tag, 0, tag.length);
		counter.set(counter.length - 1, counter.get(counter.length - 1) | 0x80);

		var k = Bytes.alloc(AES_BLOCK_SIZE);
		var i = 0;
		while (i < input.length) {
			encryptBlock(counter, 0, k, 0);
			var len = Std.int(Math.min(AES_BLOCK_SIZE, input.length - i));
			for (j in 0...len) {
				output.set(i + j, input.get(i + j) ^ k.get(j));
			}

			var carry = 1;
			for (j in 0...4) {
				var val = counter.get(j) + carry;
				counter.set(j, val & 0xFF);
				carry = val >>> 8;
				if (carry == 0)
					break;
			}
			i += AES_BLOCK_SIZE;
		}
	}

	public static inline function putInt(n:Int, b:Bytes, offset:Int = 0) {
		b.set(offset, n & 0xFF);
		b.set(offset + 1, (n >> 8) & 0xFF);
		b.set(offset + 2, (n >> 16) & 0xFF);
		b.set(offset + 3, (n >> 24) & 0xFF);
	}

	public static inline function putLong(n:Int, b:Bytes, offset:Int) {
		var hi = n & 0xFFFFFFFF;
		var lo = 0;

		b.set(offset, hi & 0xFF);
		b.set(offset + 1, (hi >> 8) & 0xFF);
		b.set(offset + 2, (hi >> 16) & 0xFF);
		b.set(offset + 3, (hi >> 24) & 0xFF);
		b.set(offset + 4, 0);
		b.set(offset + 5, 0);
		b.set(offset + 6, 0);
		b.set(offset + 7, 0);
	}

	public static inline function getInt(b:Bytes, offset:Int):Int32 {
		return (b.get(offset) & 0xFF) | ((b.get(offset + 1) & 0xFF) << 8) | ((b.get(offset + 2) & 0xFF) << 16) | (b.get(offset + 3) << 24);
	}

	public static inline function getLong(b:Bytes, offset:Int):Int64 {
		var lo = b.get(offset) & 0xFF;
		lo |= (b.get(offset + 1) & 0xFF) << 8;
		lo |= (b.get(offset + 2) & 0xFF) << 16;
		lo |= b.get(offset + 3) << 24;

		var hi = b.get(offset + 4) & 0xFF;
		hi |= (b.get(offset + 5) & 0xFF) << 8;
		hi |= (b.get(offset + 6) & 0xFF) << 16;
		hi |= b.get(offset + 7) << 24;

		var result = Int64.make(hi, lo);
		return result;
	}

	public static inline function constantTimeCompare(a:Bytes, b:Bytes):Bool {
		if (a.length != b.length)
			return false;
		var result = 0;
		for (i in 0...a.length) {
			result |= a.get(i) ^ b.get(i);
		}
		return result == 0;
	}
}