package haxe.crypto.padding;

import haxe.io.BytesBuffer;
import haxe.io.Bytes;

class PKCS7 {
	public static function pad(ciphertext:Bytes, blockSize:Int):Bytes {
		if (blockSize > 255)
			throw "PKCS#7 padding cannot be longer than 255 bytes";
		if (blockSize < 0)
			throw "PKCS#7 padding size must be positive";
		var padding:Int = blockSize - ciphertext.length % blockSize;
		var bsize = ciphertext.length + padding;
		var buffer:Bytes = Bytes.alloc(bsize);
		buffer.blit(0, ciphertext, 0, ciphertext.length);
		for (i in ciphertext.length...bsize) {
			buffer.set(i, padding & 0xFF);
		}
		return buffer;
	}

	public static function unpad(encrypt:Bytes):Bytes {
		var len = encrypt.length;
		var padding:Int = encrypt.get(len - 1);
		// Constant-time validation to prevent padding oracle timing attacks.
		// We accumulate errors without early exit so the execution path does
		// not reveal whether the padding value is in or out of range, and so
		// the loop does not leak how many padding bytes were correct.
		var bad:Int = 0;
		// Use explicit boolean-to-int to avoid platform-specific bit-width
		// assumptions (e.g. Python arbitrary-precision ints, JS float64).
		bad |= (padding < 1) ? 1 : 0;  // non-zero if padding < 1
		bad |= (padding > len) ? 1 : 0; // non-zero if padding > len
		// Clamp block to a valid index (bad is already set for this case).
		var block = len - padding;
		if (block < 0) block = 0;
		// Check every padding byte without early exit.
		for (i in block...len) {
			bad |= encrypt.get(i) ^ padding;
		}
		if (bad != 0)
			throw "Invalid PKCS7 padding";
		return encrypt.sub(0, block);
	}
}
