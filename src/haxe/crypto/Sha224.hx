/*
 * Copyright (C)2005-2018 Haxe Foundation
 *
 * Permission is hereby granted, free of Charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERChANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package haxe.crypto;

import haxe.ds.Vector;
import haxe.io.Bytes;

/**
	Creates a Sha224 of a String.
 */
class Sha224 {
	#if php
	var hashContext:Dynamic;
	#else
	var HASH:Vector<Int>;
	var buffer:Bytes;
	var bufferPos:Int;
	var totalLength:Int;
	#end

	public static function encode(s:String #if haxe4, ?encoding:haxe.io.Encoding #end):String {
		#if php
		#if haxe4
		return php.Global.hash('sha224', s);
		#else
		return untyped __php__("hash('sha224', {0})", s);
		#end
		#else
		var sh = new Sha224();
		var data = haxe.io.Bytes.ofString(s #if haxe4, encoding #end);
		var h = sh.doEncode(data);
		return sh.hex(h);
		#end
	}

	public static function make(b:haxe.io.Bytes):haxe.io.Bytes {
		#if php
		#if haxe4
		return haxe.io.Bytes.ofData(php.Global.hash('sha224', b.getData(), true));
		#else
		return haxe.io.Bytes.ofData(untyped __php__("hash('sha224', {0}, true)", b.getData()));
		#end
		#else
		var h = new Sha224().doEncode(b);
		var out = haxe.io.Bytes.alloc(28);
		var p = 0;
		for (i in 0...7) {
			out.set(p++, h[i] >>> 24);
			out.set(p++, (h[i] >> 16) & 0xFF);
			out.set(p++, (h[i] >> 8) & 0xFF);
			out.set(p++, h[i] & 0xFF);
		}
		return out;
		#end
	}

	public function new() {
		#if php
		hashContext = php.Global.hash_init('sha224');
		#else
		HASH = Vector.fromArrayCopy([
			0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
			0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
		]);
		buffer = Bytes.alloc(64);
		bufferPos = 0;
		totalLength = 0;
		#end
	}
	
	public function update(data:Bytes):Void {
		#if php
		php.Global.hash_update(hashContext, data.getData());
		#else
		var pos = 0;
		var len = data.length;
		totalLength += len;

		while (len > 0) {
			var toCopy = 64 - bufferPos;
			if (toCopy > len) toCopy = len;

			buffer.blit(bufferPos, data, pos, toCopy);
			bufferPos += toCopy;
			pos += toCopy;
			len -= toCopy;

			if (bufferPos == 64) {
				processBlock(buffer, 0);
				bufferPos = 0;
			}
		}
		#end
	}

	public function digest():Bytes {
		#if php
		return Bytes.ofData(php.Global.hash_final(hashContext, true));
		#else
		var finalBuffer = Bytes.alloc(64);
		finalBuffer.blit(0, buffer, 0, bufferPos);
		
		var pos = bufferPos;
		finalBuffer.set(pos, 0x80);
		pos++;

		if (pos > 56) {
			for (i in pos...64) {
				finalBuffer.set(i, 0);
			}
			processBlock(finalBuffer, 0);
			pos = 0;
			for (i in 0...64) {
				finalBuffer.set(i, 0);
			}
		} else {
			for (i in pos...56) {
				finalBuffer.set(i, 0);
			}
		}

		var bitLengthHigh = 0; // if message < 536MB, high part is 0
		var bitLengthLow = totalLength * 8;
		
		finalBuffer.set(56, (bitLengthHigh >>> 24) & 0xFF);
		finalBuffer.set(57, (bitLengthHigh >>> 16) & 0xFF);
		finalBuffer.set(58, (bitLengthHigh >>> 8) & 0xFF);
		finalBuffer.set(59, bitLengthHigh & 0xFF);
		finalBuffer.set(60, (bitLengthLow >>> 24) & 0xFF);
		finalBuffer.set(61, (bitLengthLow >>> 16) & 0xFF);
		finalBuffer.set(62, (bitLengthLow >>> 8) & 0xFF);
		finalBuffer.set(63, bitLengthLow & 0xFF);

		processBlock(finalBuffer, 0);

		var out = haxe.io.Bytes.alloc(28);
		var p = 0;
		for (i in 0...7) {
			out.set(p++, HASH[i] >>> 24);
			out.set(p++, (HASH[i] >> 16) & 0xFF);
			out.set(p++, (HASH[i] >> 8) & 0xFF);
			out.set(p++, HASH[i] & 0xFF);
		}

		return out;
		#end
	}

	function processBlock(block:Bytes, offset:Int):Void {
		#if !php
		var K:Vector<Int> = Vector.fromArrayCopy([
			0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
			0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
			0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
			0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
			0xE49B69C1, 0xEFBE4786,  0xFC19DC6, 0x240CA1CC,
			0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
			0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
			0xC6E00BF3, 0xD5A79147,  0x6CA6351, 0x14292967,
			0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
			0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
			0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
			0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
			0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
			0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
			0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
			0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
		]);

		var W = new Vector<Int>(64);
		
		for (j in 0...16) {
			W[j] = bytesToInt(block, offset + j * 4);
		}
		
		for (j in 16...64) {
			W[j] = safeAdd(safeAdd(safeAdd(Gamma1(W[j - 2]), W[j - 7]), Gamma0(W[j - 15])), W[j - 16]);
		}

		var a = HASH[0];
		var b = HASH[1];
		var c = HASH[2];
		var d = HASH[3];
		var e = HASH[4];
		var f = HASH[5];
		var g = HASH[6];
		var h = HASH[7];

		for (j in 0...64) {
			var T1 = safeAdd(safeAdd(safeAdd(safeAdd(h, Sigma1(e)), Ch(e, f, g)), K[j]), W[j]);
			var T2 = safeAdd(Sigma0(a), Maj(a, b, c));

			h = g;
			g = f;
			f = e;
			e = safeAdd(d, T1);
			d = c;
			c = b;
			b = a;
			a = safeAdd(T1, T2);
		}

		HASH[0] = safeAdd(a, HASH[0]);
		HASH[1] = safeAdd(b, HASH[1]);
		HASH[2] = safeAdd(c, HASH[2]);
		HASH[3] = safeAdd(d, HASH[3]);
		HASH[4] = safeAdd(e, HASH[4]);
		HASH[5] = safeAdd(f, HASH[5]);
		HASH[6] = safeAdd(g, HASH[6]);
		HASH[7] = safeAdd(h, HASH[7]);
		#end
	}

	function doEncode(data:haxe.io.Bytes):Vector<Int> {
		var K:Vector<Int> = Vector.fromArrayCopy([
			0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
			0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
			0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
			0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
			0xE49B69C1, 0xEFBE4786,  0xFC19DC6, 0x240CA1CC,
			0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
			0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
			0xC6E00BF3, 0xD5A79147,  0x6CA6351, 0x14292967,
			0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
			0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
			0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
			0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
			0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
			0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
			0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
			0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
		]);
		var HASH:Vector<Int> = Vector.fromArrayCopy([
			0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
			0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
		]);
		var W = new Vector<Int>(65);
		W[64] = 0;

		var a:Int, b:Int, c:Int, d:Int, e:Int, f:Int, g:Int, h:Int, i:Int, j:Int;
		var T1, T2;
		var i:Int = 0;
		var blocks:Vector<Int> = str2blks(data);

		while (i < blocks.length) {
			a = HASH[0];
			b = HASH[1];
			c = HASH[2];
			d = HASH[3];
			e = HASH[4];
			f = HASH[5];
			g = HASH[6];
			h = HASH[7];

			for (j in 0...64) {
				if (j < 16) {
					W[j] = blocks[j + i];
				} else {
					W[j] = safeAdd(safeAdd(safeAdd(Gamma1(W[j - 2]), W[j - 7]), Gamma0(W[j - 15])), W[j - 16]);
				}

				T1 = safeAdd(safeAdd(safeAdd(safeAdd(h, Sigma1(e)), Ch(e, f, g)), K[j]), W[j]);
				T2 = safeAdd(Sigma0(a), Maj(a, b, c));

				h = g;
				g = f;
				f = e;
				e = safeAdd(d, T1);
				d = c;
				c = b;
				b = a;
				a = safeAdd(T1, T2);
			}

			HASH[0] = safeAdd(a, HASH[0]);
			HASH[1] = safeAdd(b, HASH[1]);
			HASH[2] = safeAdd(c, HASH[2]);
			HASH[3] = safeAdd(d, HASH[3]);
			HASH[4] = safeAdd(e, HASH[4]);
			HASH[5] = safeAdd(f, HASH[5]);
			HASH[6] = safeAdd(g, HASH[6]);
			HASH[7] = safeAdd(h, HASH[7]);
			i += 16;
		}
		return HASH;
	}

	static function str2blks(data:haxe.io.Bytes):Vector<Int> {
		var nblk:Int = data.length;
		data = haxe.crypto.padding.BitPadding.pad(data, 8);
		var blksLenght = (data.length >> 2);
		blksLenght += 16 - blksLenght % 16;
		var blks = new Vector<Int>(blksLenght);
		var i = 0;
		var pos = 0;
		while (i < data.length) {
			blks[pos] = bytesToInt(data, i);
			i += 4;
			pos++;
		}
		var padding:Int = 16 - pos % 16;
		for (j in 0...padding) {
			blks[pos] = 0;
			pos++;
		}

		blks[blks.length - 1] = nblk * 8;

		return blks;
	}

	private static function bytesToInt(bs:haxe.io.Bytes, off:Int):Int {
		var n:Int = (bs.get(off)) << 24;
		n |= (bs.get(++off)) << 16;
		n |= (bs.get(++off)) << 8;
		n |= bs.get(++off);
		return n;
	}

	extern inline static function safeAdd(x, y) {
		var lsw = (x & 0xFFFF) + (y & 0xFFFF);
		var msw = (x >>> 16) + (y >>> 16) + (lsw >>> 16);
		return ((msw & 0xFFFF) << 16) | (lsw & 0xFFFF);
	}

	// ++
	extern inline function ROTR(X, n) {
		return (X >>> n) | (X << (32 - n));
	}

	// ++
	extern inline function SHR(X, n) {
		return (X >>> n);
	}

	// ++
	extern inline function Ch(x, y, z) {
		return ((x & y) ^ ((~x) & z));
	}

	// ++
	extern inline function Maj(x, y, z) {
		return ((x & y) ^ (x & z) ^ (y & z));
	}

	extern inline function Sigma0(x) {
		return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
	}

	extern inline function Sigma1(x) {
		return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
	}

	extern inline function Gamma0(x) {
		return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
	}

	extern inline function Gamma1(x) {
		return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
	}

	function hex(a:Vector<Int>) {
		var str = "";
		for (num in a) {
			str += StringTools.hex(num, 8);
		}
		return str.substring(0, 56).toLowerCase();
	}
}
