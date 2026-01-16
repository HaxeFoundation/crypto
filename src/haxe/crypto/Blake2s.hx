package haxe.crypto;

import haxe.io.Bytes;
import haxe.ds.Vector;

class Blake2s {
	static inline var BLOCK_SIZE = 64;
	static inline var OUT_SIZE = 32;

	static var IV:Vector<Int> = Vector.fromArrayCopy([
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	]);

	static var SIGMA:Vector<Vector<Int>> = Vector.fromArrayCopy([
		Vector.fromArrayCopy([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
		Vector.fromArrayCopy([14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3]),
		Vector.fromArrayCopy([11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4]),
		Vector.fromArrayCopy([7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8]),
		Vector.fromArrayCopy([9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13]),
		Vector.fromArrayCopy([2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9]),
		Vector.fromArrayCopy([12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11]),
		Vector.fromArrayCopy([13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10]),
		Vector.fromArrayCopy([6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5]),
		Vector.fromArrayCopy([10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0])
	]);

	var h:Vector<Int>;
	var t:Vector<Int>;
	var buf:Bytes;
	var buflen:Int;
	var outlen:Int;

	public function new(outlen:Int = 32, key:Bytes = null) {
		if (outlen < 1 || outlen > 32)
			throw "Invalid output length";
		this.outlen = outlen;

		h = new Vector<Int>(8);
		for (i in 0...8)
			h[i] = IV[i];
		h[0] ^= 0x01010000 | (key != null ? key.length << 8 : 0) | outlen;

		t = new Vector<Int>(2);
		t[0] = 0;
		t[1] = 0;

		buf = Bytes.alloc(BLOCK_SIZE);
		buflen = 0;

		if (key != null && key.length > 0) {
			update(key);
			buflen = BLOCK_SIZE;
		}
	}

	static inline function rotr32(x:Int, n:Int):Int {
		return (x >>> n) | (x << (32 - n));
	}

	inline function g(v:Vector<Int32>, a:Int, b:Int, c:Int, d:Int, x:Int, y:Int) {
		v[a] = (v[a] + v[b] + x) | 0;
		v[d] = rotr32(v[d] ^ v[a], 16);
		v[c] = (v[c] + v[d]) | 0;
		v[b] = rotr32(v[b] ^ v[c], 12);
		v[a] = (v[a] + v[b] + y) | 0;
		v[d] = rotr32(v[d] ^ v[a], 8);
		v[c] = (v[c] + v[d]) | 0;
		v[b] = rotr32(v[b] ^ v[c], 7);
	}

	function compress(last:Bool) {
		var v = new Vector<Int>(16);
		for (i in 0...8) {
			v[i] = h[i];
			v[i + 8] = IV[i];
		}

		v[12] ^= t[0];
		v[13] ^= t[1];
		if (last)
			v[14] = ~v[14];

		var m = new Vector<Int>(16);
		for (i in 0...16) {
			var off = i << 2;
			m[i] = buf.get(off) | (buf.get(off + 1) << 8) | (buf.get(off + 2) << 16) | (buf.get(off + 3) << 24);
		}

		for (i in 0...10) {
			var s = SIGMA[i];
			g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
			g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
			g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
			g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
			g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
			g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
			g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
			g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
		}

		for (i in 0...8)
			h[i] = (h[i] ^ v[i] ^ v[i + 8]) | 0;
	}

	public function update(data:Bytes) {
		var pos = 0;
		var len = data.length;

		while (len > 0) {
			var left = BLOCK_SIZE - buflen;
			var fill = len > left ? left : len;

			buf.blit(buflen, data, pos, fill);
			buflen += fill;
			pos += fill;
			len -= fill;

			if (buflen == BLOCK_SIZE) {
				t[0] = (t[0] + BLOCK_SIZE) | 0;
				if (t[0] < BLOCK_SIZE)
					t[1]++;
				compress(false);
				buflen = 0;
			}
		}
	}

	public function digest():Bytes {
		t[0] = (t[0] + buflen) | 0;
		if (t[0] < buflen)
			t[1]++;

		while (buflen < BLOCK_SIZE)
			buf.set(buflen++, 0);
		compress(true);

		var out = Bytes.alloc(outlen);
		for (i in 0...outlen) {
			out.set(i, (h[i >> 2] >> ((i & 3) << 3)) & 0xff);
		}
		return out;
	}

	public static function hash(data:Bytes, outlen:Int = 32, key:Bytes = null):Bytes {
		var ctx = new Blake2s(outlen, key);
		ctx.update(data);
		return ctx.digest();
	}
}