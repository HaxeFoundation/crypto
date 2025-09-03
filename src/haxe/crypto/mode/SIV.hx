package haxe.crypto.mode;

import haxe.crypto.padding.BitPadding;
import haxe.io.Bytes;

class SIV {
	/**
	 * Encrypts plaintext using AES-SIV authenticated encryption
	 * @param key The SIV master key (double AES key size: 32 bytes for AES-128-SIV, 48 bytes for  AES-192-SIV or 64 bytes for AES-256-SIV)
	 * @param plaintext The data to encrypt
	 * @param nonce Optional nonce vector 
	 * @param associatedData Optional array of additional authenticated data 
	 * @param encryptBlock Pointer for block encryption
	 * @param initKey Pointer to initialize cipher
	 * @return Encrypted ciphertext with synthetic IV prepended (IV + ciphertext)
	 */
	public static function encrypt(key:Bytes, plaintext:Bytes, ?nonce:Bytes, ?associatedData:Array<Bytes>, encryptBlock:Bytes->Int->Bytes->Int->Void,
			initKey:Bytes->?Bytes->Void):Bytes {
		if (associatedData == null)
			associatedData = [];

		if (plaintext.length > (0x7FFFFFFF - 16)) {
			throw "Text to encrypt is too long";
		}

		if (key.length != 64 && key.length != 48 && key.length != 32) {
			throw "Key should be 32, 48, or 64 bytes (256, 384, 512 bits)";
		}

		var subkeyLen = key.length >> 1;
		var macKey = key.sub(0, subkeyLen);
		var ctrKey = key.sub(subkeyLen, subkeyLen);
		var iv = s2v(macKey, plaintext, associatedData, nonce, encryptBlock, initKey);
		var ciphertext = computeCtr(plaintext, ctrKey, iv, encryptBlock, initKey);
		var result = Bytes.alloc(iv.length + ciphertext.length);
		result.blit(0, iv, 0, iv.length);
		result.blit(iv.length, ciphertext, 0, ciphertext.length);
		initKey(key,nonce); // Revert key
		return result;
	}

	/**
	 * Decrypts ciphertext using AES-SIV authenticated encryption with integrity verification
	 * @param combinedKey The SIV master key (double AES key size: 32 bytes for AES-128-SIV, 48 bytes for  AES-192-SIV or 64 bytes for AES-256-SIV)
	 * @param ciphertext The encrypted data with synthetic IV prepended (minimum 16 bytes for IV)
	 * @param nonce Optional nonce  vector
	 * @param associatedData Optional array of additional authenticated data
	 * @param encryptBlock Pointer for block encryption
	 * @param initKey Pointer to initialize cipher
	 * @return Decrypted plaintext if authentication succeeds, null if fails
	 */
	public static function decrypt(combinedKey:Bytes, ciphertext:Bytes, ?nonce:Bytes, ?associatedData:Array<Bytes>, encryptBlock:Bytes->Int->Bytes->Int->Void,
			initKey:Bytes->?Bytes->Void):Bytes {
		if (combinedKey.length != 64 && combinedKey.length != 48 && combinedKey.length != 32) {
			throw "Key should be 32, 48, or 64 bytes (256, 384, 512 bits)";
		}

		var subkeyLen = Std.int(combinedKey.length / 2);
		var macKey = combinedKey.sub(0, subkeyLen);
		var ctrKey = combinedKey.sub(subkeyLen, subkeyLen);

		if (associatedData == null)
			associatedData = [];

		if (ciphertext.length < 16) {
			throw "Input length must be greater than or equal 16";
		}

		var iv = ciphertext.sub(0, 16);
		var actualCiphertext = ciphertext.sub(16, ciphertext.length - 16);
		var plaintext = computeCtr(actualCiphertext, ctrKey, iv, encryptBlock, initKey);
		var control = s2v(macKey, plaintext, associatedData, nonce, encryptBlock, initKey);

		initKey(combinedKey,nonce); // Revert key

		var diff = 0;
		for (i in 0...iv.length) {
			diff |= iv.get(i) ^ control.get(i);
		}

		if (diff == 0) {
			return plaintext;
		} else {
			return null;
		}
	}

	static function computeCtr(input:Bytes, key:Bytes, iv:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void, initKey:Bytes->?Bytes->Void):Bytes {
		var adjustedIv = Bytes.alloc(16);
		adjustedIv.blit(0, iv, 0, 16);
		adjustedIv.set(8, adjustedIv.get(8) & 0x7F);
		adjustedIv.set(12, adjustedIv.get(12) & 0x7F);

		initKey(key,iv);
		CTR.encrypt(input, adjustedIv, 16, encryptBlock);
		return input;
	}

	static function s2v(macKey:Bytes, plaintext:Bytes, associatedData:Array<Bytes>, ?nonce:Bytes, encryptBlock:Bytes->Int->Bytes->Int->Void,
			initKey:Bytes->?Bytes->Void):Bytes {
		if (associatedData.length > 126) {
			throw "Too many associatedData fields";
		}
		initKey(macKey,nonce);
		var d = CMAC.generate(Bytes.alloc(16), macKey, 16, encryptBlock);
		for (s in associatedData) {
			var mac = CMAC.generate(s, macKey, 16, encryptBlock);
			var ddbl = dbl(d);
			d = xor(ddbl, mac);
		}
		if (nonce != null) {
			var mac = CMAC.generate(nonce, macKey, 16, encryptBlock);
			var ddbl = dbl(d);
			d = xor(ddbl, mac);
		}
		var t:Bytes;
		if (plaintext.length >= 16) {
			t = xorend(plaintext, d);
		} else {
			var padded = BitPadding.pad(plaintext, 16);
			t = xor(dbl(d), padded);
		}
		var mf = CMAC.generate(t, macKey, 16, encryptBlock);
		return mf;
	}

	static function shiftLeft(block:Bytes, output:Bytes):Int {
		var i = block.length;
		var bit = 0;
		while (--i >= 0) {
			var b = block.get(i) & 0xff;
			output.set(i, (b << 1) | bit);
			bit = (b >>> 7) & 1;
		}
		return bit;
	}

	static function dbl(input:Bytes):Bytes {
		var ret = Bytes.alloc(input.length);
		var carry = shiftLeft(input, ret);
		var mask = (-carry) & 0xff;
		ret.set(input.length - 1, ret.get(input.length - 1) ^ (0x87 & mask));

		return ret;
	}

	static function xor(in1:Bytes, in2:Bytes):Bytes {
		if (in1.length > in2.length) {
			throw "in1.length must be <= in2.length";
		}
		var result = Bytes.alloc(in1.length);
		for (i in 0...result.length) {
			result.set(i, in1.get(i) ^ in2.get(i));
		}
		return result;
	}

	static function xorend(in1:Bytes, in2:Bytes):Bytes {
		if (in1.length < in2.length) {
			throw "in1.length must be >= in2.length";
		}
		var result = Bytes.alloc(in1.length);
		result.blit(0, in1, 0, in1.length);
		var diff = in1.length - in2.length;
		for (i in 0...in2.length) {
			result.set(i + diff, result.get(i + diff) ^ in2.get(i));
		}
		return result;
	}
}