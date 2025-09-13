package haxe.crypto.mode;

import haxe.io.Bytes;
import haxe.crypto.Aes;

/**
 * AES Key Wrap with Padding (KWP) 
 * Implements  RFC 5649 (Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm) 
 */
class KWP {
	private static inline var BLOCK_SIZE:Int = 16;
	private static inline var SEMIBLOCK_SIZE:Int = 8;
	private static var KWP_IV_PREFIX:Bytes = Bytes.ofHex("A65959A6");
	private static inline var KWP_MAX_LEN:Int = 0x7FFFFFF;
	private static var aes:Aes;

	public static function encrypt(src:Bytes, key:Bytes, iv:Bytes):Bytes {
		if (src.length > KWP_MAX_LEN) {
			throw "Data too long for KWP mode";
		}
		if (src.length == 0) {
			throw "Cannot wrap empty data";
		}
		if (aes == null) {
			aes = new Aes(key, iv);
		} else {
			aes.init(key, iv);
		}
		var kwpIV = Bytes.alloc(SEMIBLOCK_SIZE);
		kwpIV.blit(0, KWP_IV_PREFIX, 0, 4);
		kwpIV.set(4, (src.length >> 24) & 0xFF);
		kwpIV.set(5, (src.length >> 16) & 0xFF);
		kwpIV.set(6, (src.length >> 8) & 0xFF);
		kwpIV.set(7, src.length & 0xFF);
		var paddedLength = Math.ceil(src.length / SEMIBLOCK_SIZE) * SEMIBLOCK_SIZE;
		var n = Math.floor(paddedLength / SEMIBLOCK_SIZE);
		if (n == 1) {
			var block = Bytes.alloc(BLOCK_SIZE);
			block.blit(0, kwpIV, 0, SEMIBLOCK_SIZE);
			block.blit(SEMIBLOCK_SIZE, src, 0, src.length);
			aes.encryptBlock(block, 0, block, 0);
			return block;
		} else {
			var paddedData = Bytes.alloc(paddedLength);
			paddedData.blit(0, src, 0, src.length);
			return KW.encryptBlock(paddedData, key, iv, aes.encryptBlock, kwpIV);
		}
	}

	public static function decrypt(src:Bytes, key:Bytes, iv:Bytes):Bytes {
		if (src.length < BLOCK_SIZE || src.length % SEMIBLOCK_SIZE != 0) {
			return null;
		}
		if (aes == null) {
			aes = new Aes(key, iv);
		} else {
			aes.init(key, iv);
		}
		var extractedIV:Bytes;
		var unwrappedData:Bytes;
		if (src.length == BLOCK_SIZE) {
			var block = Bytes.alloc(BLOCK_SIZE);
			block.blit(0, src, 0, BLOCK_SIZE);
			aes.decryptBlock(block, 0, block, 0);
			extractedIV = block.sub(0, SEMIBLOCK_SIZE);
			unwrappedData = block.sub(SEMIBLOCK_SIZE, SEMIBLOCK_SIZE);
		} else {
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
			extractedIV = a;
			unwrappedData = Bytes.alloc(n * SEMIBLOCK_SIZE);
			for (i in 0...n) {
				unwrappedData.blit(i * SEMIBLOCK_SIZE, r[i], 0, SEMIBLOCK_SIZE);
			}
		}
		if (!constantTimeEquals(extractedIV.sub(0, 4), KWP_IV_PREFIX)) {
			return null;
		}
		var mli = (extractedIV.get(4) << 24) | (extractedIV.get(5) << 16) | (extractedIV.get(6) << 8) | extractedIV.get(7);
		if (mli < 0 || mli > KWP_MAX_LEN) {
			return null;
		}
		var maxValidMLI = unwrappedData.length;
		var minValidMLI = maxValidMLI > SEMIBLOCK_SIZE ? maxValidMLI - SEMIBLOCK_SIZE + 1 : 1;
		if (mli < minValidMLI || mli > maxValidMLI) {
			return null;
		}
		for (i in mli...unwrappedData.length) {
			if (unwrappedData.get(i) != 0) {
				return null;
			}
		}
		return unwrappedData.sub(0, mli);
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
