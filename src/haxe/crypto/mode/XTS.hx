package haxe.crypto.mode;

import haxe.io.Bytes;
import haxe.crypto.Aes;
import haxe.Int64;

class XTS {
	private static var aes1:Aes;
	private static var aes2:Aes;

	/**
	 * Encrypts plaintext using AES-XTS
	 * @param src plaintext data
	 * @param key1  first AES key (for data encryption)
	 * @param key2  second AES key (for tweak encryption)
	 * @param sectorNumber The sector/block number (for tweak)
	 * @param blockSize Cipher block size
	 * @return  Ciphertext
	 */
	public static function encrypt(src:Bytes, key1:Bytes, key2:Bytes, sectorNumber:Int64, blockSize:Int=16):Bytes {
		if (src.length == 0) {
			return Bytes.alloc(0);
		}
		if (src.length < blockSize) {
			throw "XTS requires data to be at least one block size (16 bytes for AES)";
		}
		if (aes1 == null) {
			aes1 = new Aes(key1);
		} else {
			aes1.init(key1);
		}
		if (aes2 == null) {
			aes2 = new Aes(key2);
		} else {
			aes2.init(key2);
		}
		var result = src.sub(0, src.length);
		var fullBlocks = Math.floor(src.length / blockSize);
		var remainder = src.length % blockSize;
		var tweak = generateInitialTweak(sectorNumber, blockSize, aes2.encryptBlock);
		for (i in 0...fullBlocks) {
			var blockOffset = i * blockSize;
			var block = result.sub(blockOffset, blockSize);
			xorBlock(block, tweak);
			aes1.encryptBlock(block, 0, block, 0);
			xorBlock(block, tweak);
			result.blit(blockOffset, block, 0, blockSize);
			if (i < fullBlocks - 1 || remainder > 0) {
				tweak = multiplyByAlpha(tweak);
			}
		}
		if (remainder > 0) {
			var lastFullBlockOffset = (fullBlocks - 1) * blockSize;
			var partialBlockOffset = fullBlocks * blockSize;
			var lastBlock = result.sub(lastFullBlockOffset, blockSize);
			var partialBlock = result.sub(partialBlockOffset, remainder);
			var paddedBlock = Bytes.alloc(blockSize);
			paddedBlock.blit(0, partialBlock, 0, remainder);
			paddedBlock.blit(remainder, lastBlock, remainder, blockSize - remainder);
			xorBlock(paddedBlock, tweak);
			aes1.encryptBlock(paddedBlock, 0, paddedBlock, 0);
			xorBlock(paddedBlock, tweak);
			result.blit(lastFullBlockOffset, paddedBlock, 0, blockSize);
			result.blit(partialBlockOffset, lastBlock, 0, remainder);
		}
		return result;
	}

	/**
	 * Decrypts ciphertext using AES-XTS
	 * @param src Ciphertext
	 * @param key1 The first AES key (for data encryption)
	 * @param key2 The second AES key (for tweak encryption)
	 * @param sectorNumber The sector/block number (for tweak)
	 * @param blockSize Cipher block size
	 * @return Decrypted plaintext
	 */
	public static function decrypt(src:Bytes, key1:Bytes, key2:Bytes, sectorNumber:Int64, blockSize:Int=16):Bytes {
		if (src.length == 0) return Bytes.alloc(0);
		if (src.length < blockSize) throw "XTS requires data to be at least one block size (16 bytes for AES)";
		
		if (aes1 == null) aes1 = new Aes(key1); else aes1.init(key1);
		if (aes2 == null) aes2 = new Aes(key2); else aes2.init(key2);
		
		var result = src.sub(0, src.length);
		var m = Math.floor(src.length / blockSize);
		var remainder = src.length % blockSize;
		var tweak = generateInitialTweak(sectorNumber, blockSize, aes2.encryptBlock);
		
		if (remainder == 0) {
			for (i in 0...m) {
				var blockOffset = i * blockSize;
				var block = result.sub(blockOffset, blockSize);
				xorBlock(block, tweak);
				aes1.decryptBlock(block, 0, block, 0);
				xorBlock(block, tweak);
				result.blit(blockOffset, block, 0, blockSize);
				tweak = multiplyByAlpha(tweak);
			}
		} else {
			for (i in 0...(m-1)) {
				var blockOffset = i * blockSize;
				var block = result.sub(blockOffset, blockSize);
				xorBlock(block, tweak);
				aes1.decryptBlock(block, 0, block, 0);
				xorBlock(block, tweak);
				result.blit(blockOffset, block, 0, blockSize);
				tweak = multiplyByAlpha(tweak);
			}
			
			var CC = result.sub((m-1) * blockSize, blockSize);
			var CP = result.sub(m * blockSize, remainder);
			var tweakM1 = tweak.sub(0, blockSize);
			var tweakM = multiplyByAlpha(tweak);
			
			var PP = CC.sub(0, blockSize);
			xorBlock(PP, tweakM);
			aes1.decryptBlock(PP, 0, PP, 0);
			xorBlock(PP, tweakM);
			
			var newCM1 = Bytes.alloc(blockSize);
			newCM1.blit(0, CP, 0, remainder);
			newCM1.blit(remainder, PP, remainder, blockSize - remainder);
			
			var PM1 = newCM1.sub(0, blockSize);
			xorBlock(PM1, tweakM1);
			aes1.decryptBlock(PM1, 0, PM1, 0);
			xorBlock(PM1, tweakM1);
			
			var PM = PP.sub(0, remainder);
			
			result.blit((m-1) * blockSize, PM1, 0, blockSize);
			result.blit(m * blockSize, PM, 0, remainder);
		}
		
		return result;
	}

	static function generateInitialTweak(sectorNumber:Int64, blockSize:Int, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		var tweak = Bytes.alloc(blockSize);
		var low32 = sectorNumber.low;
		var high32 = sectorNumber.high;
		tweak.set(0, low32 & 0xFF);
		tweak.set(1, (low32 >>> 8) & 0xFF);
		tweak.set(2, (low32 >>> 16) & 0xFF);
		tweak.set(3, (low32 >>> 24) & 0xFF);
		tweak.set(4, high32 & 0xFF);
		tweak.set(5, (high32 >>> 8) & 0xFF);
		tweak.set(6, (high32 >>> 16) & 0xFF);
		tweak.set(7, (high32 >>> 24) & 0xFF);
		encryptBlock(tweak, 0, tweak, 0);
		return tweak;
	}

	static function xorBlock(block:Bytes, tweak:Bytes):Void {
		for (i in 0...block.length) {
			block.set(i, block.get(i) ^ tweak.get(i));
		}
	}

	static function multiplyByAlpha(input:Bytes):Bytes {
		var result = Bytes.alloc(16);
		var carry = 0;
		for (i in 0...16) {
			var b = input.get(i);
			result.set(i, ((b << 1) | carry) & 0xFF);
			carry = (b >>> 7) & 1;
		}
		if (carry != 0) {
			result.set(0, result.get(0) ^ 0x87);
		}
		return result;
	}

	/**
	 * Encrypting with a single key
	 * @param src plaintext data
	 * @param key The combined 256-bit/512-bit key
	 * @param sectorNumber The sector number
	 * @param blockSize Block size
	 * @return Encrypted data
	 */
	public static function encryptWithSingleKey(src:Bytes, key:Bytes, sectorNumber:Int64, blockSize:Int=16):Bytes {
		if (key.length != 32 && key.length != 64) {
			throw "XTS key must be 256 bits (32 bytes) or 512 bits (64 bytes)";
		}
		var keyLen = key.length >>> 1; // Split key in half
		var key1 = key.sub(0, keyLen);
		var key2 = key.sub(keyLen, keyLen);
		if (aes1 == null) {
			aes1 = new Aes(key1);
		} else {
			aes1.init(key1);
		}
		if (aes2 == null) {
			aes2 = new Aes(key2);
		} else {
			aes2.init(key2);
		}
		return encrypt(src, key1, key2, sectorNumber, blockSize); //, aes1.encryptBlock1, aes2.encryptBlock2
	}

	/**
	 * Decrypting with a single key
	 */
	public static function decryptWithSingleKey(src:Bytes, key:Bytes, sectorNumber:Int64, blockSize:Int=16):Bytes {
		if (key.length != 32 && key.length != 64) {
			throw "XTS key must be 256 bits (32 bytes) or 512 bits (64 bytes)";
		}
		var keyLen = key.length >>> 1;
		var key1 = key.sub(0, keyLen);
		var key2 = key.sub(keyLen, keyLen);
		if (aes1 == null) {
			aes1 = new Aes(key1);
		} else {
			aes1.init(key1);
		}
		if (aes2 == null) {
			aes2 = new Aes(key2);
		} else {
			aes2.init(key2);
		} // Tweak always uses encryption
		return decrypt(src, key1, key2, sectorNumber, blockSize);// , aes1.decryptBlock, aes2.encryptBlock
	}
}
