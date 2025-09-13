package haxe.crypto.mode;

import haxe.io.Bytes;
import haxe.crypto.Aes;

/**
 * AES Key Wrap (KW) implementation.
 * Implements RFC 3394 (AES Key Wrap Algorithm) 
 */
class KW {
	private static inline var BLOCK_SIZE:Int = 16;
	private static inline var SEMIBLOCK_SIZE:Int = 8;
	private static var DEFAULT_IV:Bytes = Bytes.ofHex("A6A6A6A6A6A6A6A6");

	private static var aes:Aes;

	public static function encrypt(src:Bytes, key:Bytes, iv:Bytes, ?customIV:Bytes):Bytes {
		if (aes == null) {
			aes = new Aes(key, iv);
		} else {
			aes.init(key, iv);
		}
		return KW.encryptBlock(src, key, iv, aes.encryptBlock, customIV);
	}

	public static function encryptBlock(src:Bytes, key:Bytes, iv:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void, ?customIV:Bytes):Bytes {
		if (src.length < 16 || src.length % SEMIBLOCK_SIZE != 0) {
			throw "Key wrap input must be at least 16 bytes and multiple of 8 bytes";
		}
		var initialValue = customIV != null ? customIV : DEFAULT_IV;
		if (initialValue.length != SEMIBLOCK_SIZE) {
			throw "Initial value must be exactly 8 bytes";
		}
		var n = Math.floor(src.length / SEMIBLOCK_SIZE);
		var r = new Array<Bytes>();
		for (i in 0...n) {
			r.push(src.sub(i * SEMIBLOCK_SIZE, SEMIBLOCK_SIZE));
		}
		var a = Bytes.alloc(SEMIBLOCK_SIZE);
		a.blit(0, initialValue, 0, SEMIBLOCK_SIZE);
		for (j in 0...6) {
			for (i in 0...n) {
				var b = Bytes.alloc(BLOCK_SIZE);
				b.blit(0, a, 0, SEMIBLOCK_SIZE);
				b.blit(SEMIBLOCK_SIZE, r[i], 0, SEMIBLOCK_SIZE);
				encryptBlock(b, 0, b, 0);
				var t = (n * j) + i + 1;
				a = b.sub(0, SEMIBLOCK_SIZE);
				a.set(SEMIBLOCK_SIZE - 4, a.get(SEMIBLOCK_SIZE - 4) ^ ((t >> 24) & 0xFF));
				a.set(SEMIBLOCK_SIZE - 3, a.get(SEMIBLOCK_SIZE - 3) ^ ((t >> 16) & 0xFF));
				a.set(SEMIBLOCK_SIZE - 2, a.get(SEMIBLOCK_SIZE - 2) ^ ((t >> 8) & 0xFF));
				a.set(SEMIBLOCK_SIZE - 1, a.get(SEMIBLOCK_SIZE - 1) ^ (t & 0xFF));

				r[i] = b.sub(SEMIBLOCK_SIZE, SEMIBLOCK_SIZE);
			}
		}
		var result = Bytes.alloc((n + 1) * SEMIBLOCK_SIZE);
		result.blit(0, a, 0, SEMIBLOCK_SIZE);
		for (i in 0...n) {
			result.blit((i + 1) * SEMIBLOCK_SIZE, r[i], 0, SEMIBLOCK_SIZE);
		}
		return result;
	}

	public static function decrypt(src:Bytes, key:Bytes, iv:Bytes, ?customIV:Bytes):Bytes {
		if (src.length < 24 || src.length % SEMIBLOCK_SIZE != 0) {
			return null;
		}
		var expectedIV = customIV != null ? customIV : DEFAULT_IV;
		if (expectedIV.length != SEMIBLOCK_SIZE) {
			return null;
		}
		if (aes == null) {
			aes = new Aes(key, iv);
		} else {
			aes.init(key, iv);
		}
		var n = Math.floor(src.length / SEMIBLOCK_SIZE) - 1;
		var r = new Array<Bytes>();
		var a = Bytes.alloc(SEMIBLOCK_SIZE);
		a.blit(0, src, 0, SEMIBLOCK_SIZE);
		for (i in 0...n) {
			var rBlock = Bytes.alloc(SEMIBLOCK_SIZE);
			rBlock.blit(0, src, (i + 1) * SEMIBLOCK_SIZE, SEMIBLOCK_SIZE);
			r.push(rBlock);
		}
		for (j in 0...6) {
			var jVal = 5 - j;
			for (i in 0...n) {
				var iVal = n - i;
				var t = n * jVal + iVal;
				a.set(SEMIBLOCK_SIZE - 4, a.get(SEMIBLOCK_SIZE - 4) ^ ((t >> 24) & 0xFF));
				a.set(SEMIBLOCK_SIZE - 3, a.get(SEMIBLOCK_SIZE - 3) ^ ((t >> 16) & 0xFF));
				a.set(SEMIBLOCK_SIZE - 2, a.get(SEMIBLOCK_SIZE - 2) ^ ((t >> 8) & 0xFF));
				a.set(SEMIBLOCK_SIZE - 1, a.get(SEMIBLOCK_SIZE - 1) ^ (t & 0xFF));
				var b = Bytes.alloc(BLOCK_SIZE);
				b.blit(0, a, 0, SEMIBLOCK_SIZE);
				b.blit(SEMIBLOCK_SIZE, r[iVal - 1], 0, SEMIBLOCK_SIZE);
				aes.decryptBlock(b, 0, b, 0);
				a.blit(0, b, 0, SEMIBLOCK_SIZE);
				r[iVal - 1].blit(0, b, SEMIBLOCK_SIZE, SEMIBLOCK_SIZE);
			}
		}
		if (!constantTimeEquals(a, expectedIV)) {
			return null;
		}
		var result = Bytes.alloc(n * SEMIBLOCK_SIZE);
		for (i in 0...n) {
			result.blit(i * SEMIBLOCK_SIZE, r[i], 0, SEMIBLOCK_SIZE);
		}
		return result;
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
