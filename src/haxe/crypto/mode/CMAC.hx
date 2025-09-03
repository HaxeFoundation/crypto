package haxe.crypto.mode;

import haxe.io.Bytes;

class CMAC {
	static var aes:Aes;

	/**
	 * Calculates AES-CMAC for message authentication
	 * @param message The input data to authenticate
	 * @param key The AES key for authentication (16, 24, or 32 bytes)
	 * @return The 16-byte CMAC authentication tag
	 */
	public static function calculate(message:Bytes, key:Bytes):Bytes {
		if (aes == null) {
			aes = new haxe.crypto.Aes(key);
		} else {
			aes.init(key);
		}
		return generate(message, key, 16, aes.encryptBlock);
	}

	/**
	 * Generate CMAC authentication tag for the given message
	 * @param message The message to authenticate
	 * @param key The encryption key (key size: 16, 24, or 32 bytes)
	 * @param blockSize The block size (16 bytes)
	 * @param encryptBlock The block encryption function
	 * @return The CMAC tag (same size as blockSize)
	 */
	public static function generate(message:Bytes, key:Bytes, blockSize:Int, encryptBlock:Bytes->Int->Bytes->Int->Void):Bytes {
		var subkeys = generateSubkeys(key, blockSize, encryptBlock);
		var k1 = subkeys.k1;
		var k2 = subkeys.k2;

		var messageLen = message.length;
		var numBlocks = Math.ceil(messageLen / blockSize);

		if (numBlocks == 0) {
			numBlocks = 1;
		}

		var lastBlock:Bytes;
		var isComplete:Bool;

		if (messageLen == 0) {
			lastBlock = Bytes.alloc(blockSize);
			lastBlock.set(0, 0x80);
			isComplete = false;
		} else if (messageLen % blockSize == 0) {
			lastBlock = message.sub(messageLen - blockSize, blockSize);
			isComplete = true;
		} else {
			var remainingBytes = messageLen % blockSize;
			lastBlock = Bytes.alloc(blockSize);
			lastBlock.blit(0, message, messageLen - remainingBytes, remainingBytes);
			lastBlock.set(remainingBytes, 0x80);
			isComplete = false;
		}

		var keyToUse = isComplete ? k1 : k2;
		for (i in 0...blockSize) {
			lastBlock.set(i, lastBlock.get(i) ^ keyToUse.get(i));
		}

		var mac = Bytes.alloc(blockSize);

		var fullBlocks = isComplete ? numBlocks - 1 : numBlocks - 1;
		for (blockIndex in 0...fullBlocks) {
			var offset = blockIndex * blockSize;
			for (i in 0...blockSize) {
				mac.set(i, mac.get(i) ^ message.get(offset + i));
			}
			encryptBlock(mac, 0, mac, 0);
		}

		for (i in 0...blockSize) {
			mac.set(i, mac.get(i) ^ lastBlock.get(i));
		}
		encryptBlock(mac, 0, mac, 0);

		return mac;
	}

	/**
	 * Verify CMAC authentication tag
	 * @param message The message to verify
	 * @param tag The received CMAC tag
	 * @param key The encryption key
	 * @param blockSize The block size
	 * @param encryptBlock The block encryption function
	 * @return True if tag is valid, false otherwise
	 */
	public static function verify(message:Bytes, tag:Bytes, key:Bytes, ?encryptBlock:Bytes->Int->Bytes->Int->Void):Bool {
		if (encryptBlock == null) {
            if (aes == null) {
			    aes = new haxe.crypto.Aes(key);
		    } else {
			    aes.init(key);
		    }
			encryptBlock = aes.encryptBlock;
		}
		var computedTag = generate(message, key, 16, encryptBlock);

		if (tag.length != computedTag.length) {
			return false;
		}

		var result = 0;
		for (i in 0...tag.length) {
			result |= tag.get(i) ^ computedTag.get(i);
		}

		return result == 0;
	}

	/**
	 * Generate the two subkeys K1 and K2 for CMAC (RFC 4493)
	 */
	private static function generateSubkeys(key:Bytes, blockSize:Int, encryptBlock:Bytes->Int->Bytes->Int->Void):{k1:Bytes, k2:Bytes} {
		var rb:Int;
		if (blockSize == 16) {
			rb = 0x87;
		} else if (blockSize == 8) {
			rb = 0x1B;
		} else {
			throw "Unsupported block size for CMAC";
		}

		var zeroBlock = Bytes.alloc(blockSize);
		var l = zeroBlock.sub(0, blockSize);
		encryptBlock(l, 0, l, 0);

		var k1 = leftShiftOnebit(l);
		if ((l.get(0) & 0x80) != 0) {
			k1.set(blockSize - 1, k1.get(blockSize - 1) ^ rb);
		}

		var k2 = leftShiftOnebit(k1);
		if ((k1.get(0) & 0x80) != 0) {
			k2.set(blockSize - 1, k2.get(blockSize - 1) ^ rb);
		}

		return {k1: k1, k2: k2};
	}

	private static function leftShiftOnebit(input:Bytes):Bytes {
		var output = Bytes.alloc(input.length);
		var carry = 0;

		for (i in 0...input.length) {
			var b = input.get(input.length - 1 - i);
			output.set(input.length - 1 - i, ((b << 1) | carry) & 0xFF);
			carry = (b & 0x80) != 0 ? 1 : 0;
		}

		return output;
	}
}
