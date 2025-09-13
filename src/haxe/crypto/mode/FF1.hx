package haxe.crypto.mode;

import haxe.io.Bytes;
import haxe.math.bigint.BigInt;
import haxe.crypto.Aes;

#if (haxe_ver >= 5)
class FF1 {
	public static final DEFAULT_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";

	private static final BASE_256 = BigInt.fromInt(256);
	private static final BASE_2 = BigInt.fromInt(2);

	private static var aes:Aes;

	/**
	 * Encrypt with FF1 Format Preserving Encryption
	 * @param plaintext String to encrypt
	 * @param key The AES key (16, 24, or 32 bytes)
	 * @param tweak Additional data
	 * @param radix The radix/base of the alphabet (10 for digits)
	 * @param alphabet The character set ( "0123456789" for digits)
	 * @param encryptBlock AES encryption function
	 * @param blockSize Block size 
	 * @return Encrypted string
	 */
	public static function encrypt(plaintext:String, key:Bytes, tweak:Bytes, radix:Int, alphabet:String, blockSize:Int = 16):String {
		if (aes == null) {
			aes = new Aes(key);
		} else {
			aes.init(key);
		}
		return cipher(plaintext, key, tweak, radix, alphabet, aes.encryptBlock, blockSize, true);
	}

	/**
	 * Decrypt with FF1 Format Preserving Encryption
	 * @param ciphertext String to decrypt
	 * @param key The AES key (16, 24, or 32 bytes)
	 * @param tweak Additional data
	 * @param radix The radix/base of the alphabet (10 for digits)
	 * @param alphabet The character set ( "0123456789" for digits)
	 * @param encryptBlock AES encryption function
	 * @param blockSize Block size
	 * @return Decrypted string
	 */
	public static function decrypt(ciphertext:String, key:Bytes, tweak:Bytes, radix:Int, alphabet:String, blockSize:Int = 16):String {
		if (aes == null) {
			aes = new Aes(key);
		} else {
			aes.init(key);
		}
		return cipher(ciphertext, key, tweak, radix, alphabet, aes.encryptBlock, blockSize, false);
	}

	private static function cipher(X:String, key:Bytes, tweak:Bytes, radix:Int, alphabet:String, encryptBlock:Bytes->Int->Bytes->Int->Void, blockSize:Int,
			encrypt:Bool):String {
		if (radix < 2 || radix > alphabet.length) {
			throw "Invalid radix";
		}
		var txtmin = Math.ceil(6.0 / Math.log(radix) / Math.log(10));
		if (txtmin < 2)
			txtmin = 2;
		if (tweak == null) {
			tweak = Bytes.alloc(0);
		}
		var n = X.length;
		var u = Math.floor(n / 2);
		var v = n - u;
		if (n < txtmin) {
			throw "Text too short (minimum " + txtmin + " characters for radix " + radix + ")";
		}
		var b = Math.floor((Math.ceil(Math.log(radix) / Math.log(2) * v) + 7) / 8);
		var d = 4 * Math.floor((b + 3) / 4) + 4;
		var p = 16;
		var r = Math.floor((d + 15) / 16) * 16;
		var q = Math.floor((tweak.length + b + 1 + 15) / 16) * 16;
		var A:String, B:String;
		var PQ:Bytes, R:Bytes;
		PQ = Bytes.alloc(p + q);
		R = Bytes.alloc(r);
		if (encrypt) {
			A = X.substring(0, u);
			B = X.substring(u);
		} else {
			B = X.substring(0, u);
			A = X.substring(u);
		}
		PQ.set(0, 1);
		PQ.set(1, 2);
		PQ.set(2, 1);
		PQ.set(3, (radix >> 16) & 0xFF);
		PQ.set(4, (radix >> 8) & 0xFF);
		PQ.set(5, radix & 0xFF);
		PQ.set(6, 10);
		PQ.set(7, u & 0xFF);
		PQ.set(8, (n >> 24) & 0xFF);
		PQ.set(9, (n >> 16) & 0xFF);
		PQ.set(10, (n >> 8) & 0xFF);
		PQ.set(11, n & 0xFF);
		PQ.set(12, (tweak.length >> 24) & 0xFF);
		PQ.set(13, (tweak.length >> 16) & 0xFF);
		PQ.set(14, (tweak.length >> 8) & 0xFF);
		PQ.set(15, tweak.length & 0xFF);
		PQ.blit(p, tweak, 0, tweak.length);
		for (i in 0...10) {
			var m = (((i + (encrypt ? 1 : 0)) % 2) == 1) ? u : v;
			var c:BigInt, y:BigInt;
			PQ.set(PQ.length - b - 1, encrypt ? i : (9 - i));
			c = stringToBigInt(B, radix, alphabet);
			var numb = c.toBytes();
			if (numb.get(0) == 0 && numb.length > 1) {
				var temp = Bytes.alloc(numb.length - 1);
				temp.blit(0, numb, 1, numb.length - 1);
				numb = temp;
			}
			if (b <= numb.length) {
				PQ.blit(PQ.length - b, numb, 0, b);
			} else {
				for (j in (PQ.length - b)...(PQ.length - numb.length)) {
					PQ.set(j, 0);
				}
				PQ.blit(PQ.length - numb.length, numb, 0, numb.length);
			}
			prf(R, 0, PQ, 0, PQ.length, encryptBlock, blockSize);
			for (j in 1...Std.int(r / 16)) {
				var l = j * 16;
				for (k in l...(l + 12)) {
					R.set(k, 0);
				}
				R.set(l + 12, (j >> 24) & 0xFF);
				R.set(l + 13, (j >> 16) & 0xFF);
				R.set(l + 14, (j >> 8) & 0xFF);
				R.set(l + 15, j & 0xFF);
				xor(R, l, R, 0, R, l, 16);
				encryptBlock(R, l, R, l);
			}
			y = bytesToBigInt(R.sub(0, d));
			var modulus = BASE_2.pow(8 * d);
			y = y % modulus;
			c = stringToBigInt(A, radix, alphabet);
			if (encrypt) {
				c = c + y;
			} else {
				c = c - y;
			}
			var radixPowM = BigInt.fromInt(radix).pow(m);
			c = c % radixPowM;
			if (c < 0) {
				c = c + radixPowM;
			}
			A = B;
			B = bigIntToString(c, m, radix, alphabet);
		}
		return encrypt ? (A + B) : (B + A);
	}

	private static function prf(dst:Bytes, doff:Int, src:Bytes, soff:Int, len:Int, encryptBlock:Bytes->Int->Bytes->Int->Void, blockSize:Int):Void {
		if ((len % blockSize) != 0) {
			throw "Invalid source length for PRF";
		}
		var cbcBlock = Bytes.alloc(blockSize);
		for (i in 0...blockSize) {
			cbcBlock.set(i, 0);
		}
		var pos = soff;
		var remaining = len;
		while (remaining > 0) {
			for (i in 0...blockSize) {
				cbcBlock.set(i, cbcBlock.get(i) ^ src.get(pos + i));
			}
			encryptBlock(cbcBlock, 0, cbcBlock, 0);
			pos += blockSize;
			remaining -= blockSize;
		}
		dst.blit(doff, cbcBlock, 0, blockSize);
	}

	private static function xor(d:Bytes, doff:Int, s1:Bytes, s1off:Int, s2:Bytes, s2off:Int, len:Int):Void {
		for (i in 0...len) {
			d.set(doff + i, s1.get(s1off + i) ^ s2.get(s2off + i));
		}
	}

	private static function stringToBigInt(str:String, radix:Int, alpha:String):BigInt {
		var result = BigInt.fromInt(0);
		var base = BigInt.fromInt(radix);

		for (i in 0...str.length) {
			var char = str.charAt(i);
			var idx = alpha.indexOf(char);
			if (idx == -1) {
				throw "Invalid character in string: " + char;
			}
			result = result * base + BigInt.fromInt(idx);
		}

		return result;
	}

	private static function bigIntToString(num:BigInt, length:Int, radix:Int, alpha:String):String {
		if (num == 0) {
			var result = "";
			for (i in 0...length) {
				result += alpha.charAt(0);
			}
			return result;
		}
		var result = "";
		var base = BigInt.fromInt(radix);
		var n = num;
		while (n > 0) {
			var remainder = n % base;
			var idx = bigIntToInt(remainder, radix);
			result = alpha.charAt(idx) + result;
			n = n / base;
		}
		if (result.length > length) {
			throw "Unable to convert BigInt into " + length + " characters";
		}
		while (result.length < length) {
			result = alpha.charAt(0) + result;
		}
		return result;
	}

	private static function bytesToBigInt(bytes:Bytes):BigInt {
		var result = BigInt.fromInt(0);
		for (i in 0...bytes.length) {
			result = result * BASE_256 + BigInt.fromInt(bytes.get(i));
		}
		return result;
	}

	private static function bigIntToInt(num:BigInt, maxExpected:Int):Int {
		var str = num.toString();
		var result = Std.parseInt(str);
		if (result == null || result < 0 || result >= maxExpected) {
			throw "BigInt value out of expected range: " + str;
		}
		return result;
	}
}
#else
class FF1 {
	public static final DEFAULT_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz";
	public static function encrypt(plaintext:String, key:Bytes, tweak:Bytes, radix:Int, alphabet:String, blockSize:Int = 16):String {
        throw "Haxe version 5 or later is required";
        return null;
    }
    public static function decrypt(ciphertext:String, key:Bytes, tweak:Bytes, radix:Int, alphabet:String, blockSize:Int = 16):String {
        throw "Haxe version 5 or later is required";
        return null;
    }
}
#end
