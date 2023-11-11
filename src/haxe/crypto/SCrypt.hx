package haxe.crypto;

import haxe.ds.Vector;
import haxe.io.Bytes;

class SCrypt {
	var pbkdf2:Pbkdf2;
	var salsa20:Salsa20;

	public function new() {
		pbkdf2 = new Pbkdf2(SHA256);
		salsa20 = new Salsa20(8);
	}

	/**
	 * Generate hash using scrypt
	 *
	 * @param password
	 * @param salt
	 * @param N - CPU / Memory cost parameter. Must be a power of 2 and between 1 and 2^(128*r/8)
	 * @param r - block size factor > 0 (8 is commonly used)
	 * @param p  - parallelization parameter (1..2^32-1 * 32/(128*r) )
	 * @param dkLen - output size
	 * @return the generated key
	 */
	public function hash(password:Bytes, salt:Bytes, N:Int, r:Int, p:Int, dkLen:Int):Bytes {
		if (password == null)
			throw "Password must not be null";
		if (salt == null)
			throw "Salt must not be null";
		if ((N < 2) || !isPowerOf2(N))
			throw "N must be > 1 and a power of 2";
		if ((r < 1) || (p < 1))
			throw "Block size r must be > 0  and p must be > 0";
		if (dkLen < 1)
			throw "dKlen must be > 0";

		var mflen:Int = 128 * r;
		var mfwords:Int = mflen >>> 2;

		var data = pbkdf2.encode(password, salt, 1, p * mflen);
		var b = new Vector<Int>(data.length >>> 2);
		for (i in 0...b.length) {
			b[i] = bytesToInt32(data, i * 4);
		}

		var xbuf = new Vector<Int>(mfwords);
		var vbuf = new Vector<Int>(N * mfwords);
		var xtbuf = new Vector<Int>(16);
		for (i in 0...p) {
			sMix(vbuf, b, i * mfwords, xbuf, xtbuf, mfwords, N, r);
		}

		var output = Bytes.alloc(data.length);
		for (i in 0...b.length) {
			int32ToBytes(b[i], output, i * 4);
		};

		return pbkdf2.encode(password, output, 1, dkLen);
	}

	private function sMix(vbuf:Vector<Int>, output:Vector<Int>, outputOffset:Int, xbuf:Vector<Int>, xtbuf:Vector<Int>, mfwords:Int, N:Int, r:Int):Void {
		Vector.blit(output, outputOffset, vbuf, 0, mfwords);
		for (i in 1...N) {
			blockMix(vbuf, (i - 1) * mfwords, vbuf, i * mfwords, mfwords, r, xtbuf);
		}
		blockMix(vbuf, (N - 1) * mfwords, output, outputOffset, mfwords, r, xtbuf);
		var j:Int = 0;
		for (i in 0...(N >> 1)) {
			j = (output.get(outputOffset + mfwords - 16) & (N - 1)) * mfwords;
			xor(output, outputOffset, vbuf, j, output, outputOffset, mfwords);
			blockMix(output, outputOffset, xbuf, 0, mfwords, r, xtbuf);
			j = (xbuf.get(mfwords - 16) & (N - 1)) * mfwords;
			xor(xbuf, 0, vbuf, j, xbuf, 0, mfwords);
			blockMix(xbuf, 0, output, outputOffset, mfwords, r, xtbuf);
		}
	}

	private function blockMix(b:Vector<Int>, bOffset:Int, output:Vector<Int>, outputOffset:Int, mfwords:Int, r:Int, xtbuf:Vector<Int>):Void {
		var x = b;
		var offset = bOffset + mfwords - 16;
		for (i in 0...(r << 1)) {
			xor(x, offset, b, bOffset + i * 16, xtbuf, 0, 16);
			offset = outputOffset + ((i & 1) * r + (i >> 1)) * 16;
			salsa20.generateBlock(xtbuf, output, 8, offset);
			x = output;
		}
	}

	private static inline function xor(a:Vector<Int>, aOffset:Int, b:Vector<Int>, bOffset:Int, output:Vector<Int>, outputOffset:Int, outputLength:Int):Void {
		for (i in 0...outputLength) {
			output.set(outputOffset + i, a.get(aOffset + i) ^ b.get(bOffset + i));
		}
	}

	public static inline function isPowerOf2(x:Int):Bool {
		return ((x & (x - 1)) == 0);
	}

	private function int32ToBytes(n:Int, bs:Bytes, off:Int):Void {
		bs.set(off, (n));
		bs.set(++off, (n >>> 8));
		bs.set(++off, (n >>> 16));
		bs.set(++off, (n >>> 24));
	}

	private function bytesToInt32(bs:Bytes, off:Int):Int32 {
		var n:Int32 = (bs.get(off));
		n |= (bs.get(++off)) << 8;
		n |= (bs.get(++off)) << 16;
		n |= bs.get(++off) << 24;
		return n;
	}
}
