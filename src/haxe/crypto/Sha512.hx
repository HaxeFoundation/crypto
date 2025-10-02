package haxe.crypto;

import haxe.ds.Vector;
import haxe.Int64;
import haxe.io.Bytes;
#if haxe4 import haxe.io.Encoding; #end

class Sha512 {
	inline static var BLOCK_LEN:Int = 128;

	#if php
	var hashContext:Dynamic;
	#else
	var state:Vector<Int64>;
	var buffer:Bytes;
	var bufferPos:Int;
	var totalLength:Int;
	#end
	
	public function new() {
		#if php
		hashContext = untyped __php__("hash_init('sha512')");
		#else
		state = Vector.fromArrayCopy([
			Int64.make(0x6A09E667, 0xF3BCC908), Int64.make(0xBB67AE85, 0x84CAA73B), Int64.make(0x3C6EF372, 0xFE94F82B), Int64.make(0xA54FF53A, 0x5F1D36F1),
			Int64.make(0x510E527F, 0xADE682D1), Int64.make(0x9B05688C, 0x2B3E6C1F), Int64.make(0x1F83D9AB, 0xFB41BD6B), Int64.make(0x5BE0CD19, 0x137E2179)
		]);
		buffer = Bytes.alloc(BLOCK_LEN);
		bufferPos = 0;
		totalLength = 0;
		#end
	}

	public static function encode(s:String #if haxe4, ?encoding:haxe.io.Encoding #end):String {
		#if php
		#if haxe4
		return php.Global.hash('sha512', s);
		#else
		return untyped __php__("hash('sha512', {0})", s);
		#end
		#else
		var data = haxe.io.Bytes.ofString(s #if haxe4, encoding #end);
		var out = new Sha512().doEncode(data);
		return out.toHex();
		#end
	}
	
	public function update(data:Bytes):Void {
		#if php
		untyped __php__("hash_update({0}, {1})", hashContext, data.getData());
		#else
		var pos = 0;
		var len = data.length;
		totalLength += len;

		while (len > 0) {
			var toCopy = BLOCK_LEN - bufferPos;
			if (toCopy > len) toCopy = len;

			buffer.blit(bufferPos, data, pos, toCopy);
			bufferPos += toCopy;
			pos += toCopy;
			len -= toCopy;

			if (bufferPos == BLOCK_LEN) {
				compress(state, buffer, BLOCK_LEN);
				bufferPos = 0;
			}
		}
		#end
	}

	public function digest():Bytes {
		#if php
		return Bytes.ofData(untyped __php__("hash_final({0}, true)", hashContext));
		#else
		var block = Bytes.alloc(BLOCK_LEN);
		block.blit(0, buffer, 0, bufferPos);
		var off = bufferPos;
		
		block.set(off, 0x80);
		off++;
		
		if (off + 16 > block.length) {
			for (i in off...block.length) {
				block.set(i, 0);
			}
			compress(state, block, block.length);
			block.fill(0, block.length, 0);
			off = 0;
		} else {
			for (i in off...block.length - 16) {
				block.set(i, 0);
			}
		}

		var len = totalLength << 3;
		for (i in 0...8) {
			if (i > 3) {
				block.set(block.length - 1 - i, 0);
			} else {
				block.set(block.length - 1 - i, (len >>> (i * 8)));
			}
		}
		compress(state, block, block.length);

		var result = Bytes.alloc(state.length * 8);
		for (i in 0...result.length)
			result.set(i, (state[i >>> 3] >>> ((7 - i % 8) * 8)).low);
		return result;
		#end
	}

	public static function make(b:haxe.io.Bytes):haxe.io.Bytes {
		#if php
		#if haxe4
		return Bytes.ofData(php.Global.hash('sha512', b.getData(), true));
		#else
		return Bytes.ofData(untyped __php__("hash('sha512', {0}, true)", b.getData()));
		#end
		#else
		var out = new Sha512().doEncode(b);
		return out;
		#end
	}

	function doEncode(msg:Bytes):Bytes {
		var state:Vector<Int64> = Vector.fromArrayCopy([
			Int64.make(0x6A09E667, 0xF3BCC908), Int64.make(0xBB67AE85, 0x84CAA73B), Int64.make(0x3C6EF372, 0xFE94F82B), Int64.make(0xA54FF53A, 0x5F1D36F1),
			Int64.make(0x510E527F, 0xADE682D1), Int64.make(0x9B05688C, 0x2B3E6C1F), Int64.make(0x1F83D9AB, 0xFB41BD6B), Int64.make(0x5BE0CD19, 0x137E2179)
		]);
		var off:Int = Math.floor(msg.length / BLOCK_LEN) * BLOCK_LEN;
		compress(state, msg, off);
		var block = Bytes.alloc(BLOCK_LEN);
		block.blit(0, msg, off, msg.length - off);
		off = msg.length % block.length;
		block.set(off, 0x80);
		off++;
		if (off + 16 > block.length) {
			compress(state, block, block.length);
			block.fill(0, block.length, 0);
		}

		var len = msg.length << 3;
		for (i in 0...8) {
			if (i > 3) {
				block.set(block.length - 1 - i, 0);
			} else {
				block.set(block.length - 1 - i, (len >>> (i * 8)));
			}
		}
		compress(state, block, block.length);

		var result = Bytes.alloc(state.length * 8);
		for (i in 0...result.length)
			result.set(i, (state[i >>> 3] >>> ((7 - i % 8) * 8)).low);
		return result;
	}

	function compress(state:Vector<Int64>, blocks:Bytes, len:Int) {
		if (len < 0 || len % BLOCK_LEN != 0)
			throw "Illegal argument";
		var i = 0;
		while (i < len) {
			var schedule:Vector<Int64> = Vector.fromArrayCopy([for (k in 0...80) Int64.make(0, 0)]);
			for (j in 0...BLOCK_LEN) {
				schedule[(j >>> 3)] |= Int64.ofInt((blocks.get(i + j) & 0xFF)) << ((7 - j % 8) * 8);
			}
			for (j in 16...80) {
				schedule[j] = schedule[j - 16]
					+ schedule[j - 7]
					+ (ror64(schedule[j - 15], 1) ^ ror64(schedule[j - 15], 8) ^ (schedule[j - 15] >>> 7))
					+ (ror64(schedule[j - 2], 19) ^ ror64(schedule[j - 2], 61) ^ (schedule[j - 2] >>> 6));
			}

			var a = state[0];
			var b = state[1];
			var c = state[2];
			var d = state[3];
			var e = state[4];
			var f = state[5];
			var g = state[6];
			var h = state[7];
			for (j in 0...80) {
				var t1 = h + (ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41)) + (g ^ (e & (f ^ g))) + ROUND_CONSTANTS[j] + schedule[j];
				var t2 = (ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39)) + ((a & (b | c)) | (b & c));
				h = g;
				g = f;
				f = e;
				e = d + t1;
				d = c;
				c = b;
				b = a;
				a = t1 + t2;
			}
			state[0] += a;
			state[1] += b;
			state[2] += c;
			state[3] += d;
			state[4] += e;
			state[5] += f;
			state[6] += g;
			state[7] += h;

			i += BLOCK_LEN;
		}
	}

	private function ror64(x:Int64, n:Int):Int64 {
		return ((x >>> n) | (x << (64 - n)));
	}

	public static var ROUND_CONSTANTS:Vector<Int64> = Vector.fromArrayCopy([
		Int64.make(0x428A2F98, 0xD728AE22), Int64.make(0x71374491, 0x23EF65CD), Int64.make(0xB5C0FBCF, 0xEC4D3B2F), Int64.make(0xE9B5DBA5, 0x8189DBBC),
		Int64.make(0x3956C25B, 0xF348B538), Int64.make(0x59F111F1, 0xB605D019), Int64.make(0x923F82A4, 0xAF194F9B), Int64.make(0xAB1C5ED5, 0xDA6D8118),
		Int64.make(0xD807AA98, 0xA3030242), Int64.make(0x12835B01, 0x45706FBE), Int64.make(0x243185BE, 0x4EE4B28C), Int64.make(0x550C7DC3, 0xD5FFB4E2),
		Int64.make(0x72BE5D74, 0xF27B896F), Int64.make(0x80DEB1FE, 0x3B1696B1), Int64.make(0x9BDC06A7, 0x25C71235), Int64.make(0xC19BF174, 0xCF692694),
		Int64.make(0xE49B69C1, 0x9EF14AD2), Int64.make(0xEFBE4786, 0x384F25E3), Int64.make(0x0FC19DC6, 0x8B8CD5B5), Int64.make(0x240CA1CC, 0x77AC9C65),
		Int64.make(0x2DE92C6F, 0x592B0275), Int64.make(0x4A7484AA, 0x6EA6E483), Int64.make(0x5CB0A9DC, 0xBD41FBD4), Int64.make(0x76F988DA, 0x831153B5),
		Int64.make(0x983E5152, 0xEE66DFAB), Int64.make(0xA831C66D, 0x2DB43210), Int64.make(0xB00327C8, 0x98FB213F), Int64.make(0xBF597FC7, 0xBEEF0EE4),
		Int64.make(0xC6E00BF3, 0x3DA88FC2), Int64.make(0xD5A79147, 0x930AA725), Int64.make(0x06CA6351, 0xE003826F), Int64.make(0x14292967, 0x0A0E6E70),
		Int64.make(0x27B70A85, 0x46D22FFC), Int64.make(0x2E1B2138, 0x5C26C926), Int64.make(0x4D2C6DFC, 0x5AC42AED), Int64.make(0x53380D13, 0x9D95B3DF),
		Int64.make(0x650A7354, 0x8BAF63DE), Int64.make(0x766A0ABB, 0x3C77B2A8), Int64.make(0x81C2C92E, 0x47EDAEE6), Int64.make(0x92722C85, 0x1482353B),
		Int64.make(0xA2BFE8A1, 0x4CF10364), Int64.make(0xA81A664B, 0xBC423001), Int64.make(0xC24B8B70, 0xD0F89791), Int64.make(0xC76C51A3, 0x0654BE30),
		Int64.make(0xD192E819, 0xD6EF5218), Int64.make(0xD6990624, 0x5565A910), Int64.make(0xF40E3585, 0x5771202A), Int64.make(0x106AA070, 0x32BBD1B8),
		Int64.make(0x19A4C116, 0xB8D2D0C8), Int64.make(0x1E376C08, 0x5141AB53), Int64.make(0x2748774C, 0xDF8EEB99), Int64.make(0x34B0BCB5, 0xE19B48A8),
		Int64.make(0x391C0CB3, 0xC5C95A63), Int64.make(0x4ED8AA4A, 0xE3418ACB), Int64.make(0x5B9CCA4F, 0x7763E373), Int64.make(0x682E6FF3, 0xD6B2B8A3),
		Int64.make(0x748F82EE, 0x5DEFB2FC), Int64.make(0x78A5636F, 0x43172F60), Int64.make(0x84C87814, 0xA1F0AB72), Int64.make(0x8CC70208, 0x1A6439EC),
		Int64.make(0x90BEFFFA, 0x23631E28), Int64.make(0xA4506CEB, 0xDE82BDE9), Int64.make(0xBEF9A3F7, 0xB2C67915), Int64.make(0xC67178F2, 0xE372532B),
		Int64.make(0xCA273ECE, 0xEA26619C), Int64.make(0xD186B8C7, 0x21C0C207), Int64.make(0xEADA7DD6, 0xCDE0EB1E), Int64.make(0xF57D4F7F, 0xEE6ED178),
		Int64.make(0x06F067AA, 0x72176FBA), Int64.make(0x0A637DC5, 0xA2C898A6), Int64.make(0x113F9804, 0xBEF90DAE), Int64.make(0x1B710B35, 0x131C471B),
		Int64.make(0x28DB77F5, 0x23047D84), Int64.make(0x32CAAB7B, 0x40C72493), Int64.make(0x3C9EBE0A, 0x15C9BEBC), Int64.make(0x431D67C4, 0x9C100D4C),
		Int64.make(0x4CC5D4BE, 0xCB3E42B6), Int64.make(0x597F299C, 0xFC657E2A), Int64.make(0x5FCB6FAB, 0x3AD6FAEC), Int64.make(0x6C44198C, 0x4A475817)
	]);
}
