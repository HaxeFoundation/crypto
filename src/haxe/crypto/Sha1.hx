/*
 * Copyright (C)2005-2019 Haxe Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
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
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

package haxe.crypto;

import haxe.io.Bytes;
#if java
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
#end

/**
	Creates a Sha1 of a String or Bytes.
**/
class Sha1 {
	#if hl
	public static function encode(s:String):String {
		var out = haxe.io.Bytes.alloc(20);
		@:privateAccess hl.Format.digest(out.b, s.bytes, s.length, 256 | 1);
		return out.toHex();
	}

	public static function make(b:haxe.io.Bytes):haxe.io.Bytes {
		var out = haxe.io.Bytes.alloc(20);
		@:privateAccess hl.Format.digest(out.b, b.b, b.length, 1);
		return out;
	}
	#elseif java
	public static function encode(s:String):String {
		return Bytes.ofData(digest((cast s : java.NativeString).getBytes(StandardCharsets.UTF_8))).toHex();
	}

	public static function make(b:haxe.io.Bytes):haxe.io.Bytes {
		return Bytes.ofData(digest(b.getData()));
	}

	inline static function digest(b:haxe.io.BytesData):haxe.io.BytesData {
		return MessageDigest.getInstance("SHA-1").digest(b);
	}
	#elseif php
	public static inline function encode(s:String):String {
		return php.Global.sha1(s);
	}

	public static inline function make(b:haxe.io.Bytes):haxe.io.Bytes {
		return Bytes.ofData(php.Global.sha1(b.getData(), true));
	}

	#else
	public static function encode(s:String):String {
		var sh = new Sha1();
		#if target.unicode
		sh.update(haxe.io.Bytes.ofString(s));
		#else
		var b = haxe.io.Bytes.alloc(s.length);
		for (i in 0...s.length) b.set(i, StringTools.fastCodeAt(s, i) & 0xFF);
		sh.update(b);
		#end
		return sh.digest().toHex();
	}

	public static function make(b:haxe.io.Bytes):haxe.io.Bytes {
		var sh = new Sha1();
		sh.update(b);
		return sh.digest();
	}
	#end

	#if java
	var digest:java.security.MessageDigest;

	public function new() {
		digest = java.security.MessageDigest.getInstance("SHA-1");
	}

	public function update(b:haxe.io.Bytes):Void {
		digest.update(b.getData());
	}

	public function digest():haxe.io.Bytes {
		return Bytes.ofData(digest.digest());
	}

	#elseif php
	var context:Dynamic;

	public function new() {
		context = php.Global.hash_init("sha1");
	}

	public function update(b:haxe.io.Bytes):Void {
		php.Global.hash_update(context, b.getData());
	}

	public function digest():haxe.io.Bytes {
		return Bytes.ofData(php.Global.hash_final(context, true));
	}

	#else
	var h:Array<Int>;
	var buffer:haxe.io.Bytes;
	var bufferLen:Int;
	var totalLen:haxe.Int64;

	public function new() {
		h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
		buffer = haxe.io.Bytes.alloc(64);
		bufferLen = 0;
		totalLen = 0;
	}

	public function update(b:haxe.io.Bytes):Void {
		if (b.length == 0) return;

		totalLen = totalLen + b.length;

		var pos = 0;
		var len = b.length;
		while (len > 0) {
			var copyLen = len < (64 - bufferLen) ? len : (64 - bufferLen);
			buffer.blit(bufferLen, b, pos, copyLen);
			bufferLen += copyLen;
			pos += copyLen;
			len -= copyLen;

			if (bufferLen == 64) {
				processBlock();
				bufferLen = 0;
			}
		}
	}

	public function digest():haxe.io.Bytes {
		buffer.set(bufferLen, 0x80);
		bufferLen++;

		if (bufferLen > 56) {
			while (bufferLen < 64) {
				buffer.set(bufferLen, 0);
				bufferLen++;
			}
			processBlock();
			bufferLen = 0;
		}

		while (bufferLen < 56) {
			buffer.set(bufferLen, 0);
			bufferLen++;
		}

		final bitLen = totalLen * 8;
		buffer.set(56, haxe.Int64.toInt((bitLen >>> 56) & 0xFF));
		buffer.set(57, haxe.Int64.toInt((bitLen >>> 48)) & 0xFF);
		buffer.set(58, haxe.Int64.toInt((bitLen >>> 40)) & 0xFF);
		buffer.set(59, haxe.Int64.toInt((bitLen >>> 32)) & 0xFF);
		buffer.set(60, haxe.Int64.toInt((bitLen >>> 24)) & 0xFF);
		buffer.set(61, haxe.Int64.toInt((bitLen >>> 16)) & 0xFF);
		buffer.set(62, haxe.Int64.toInt((bitLen >>> 8)) & 0xFF);
		buffer.set(63, haxe.Int64.toInt(bitLen) & 0xFF);

		processBlock();

		var out = haxe.io.Bytes.alloc(20);
		for (i in 0...5) {
			out.set(i * 4, h[i] >>> 24);
			out.set(i * 4 + 1, (h[i] >> 16) & 0xFF);
			out.set(i * 4 + 2, (h[i] >> 8) & 0xFF);
			out.set(i * 4 + 3, h[i] & 0xFF);
		}
		return out;
	}

	function processBlock():Void {
		var w = new Array<Int>();
		for (j in 0...16) {
			w[j] = (buffer.get(j * 4) << 24) |
			           ((buffer.get(j * 4 + 1) & 0xFF) << 16) |
			           ((buffer.get(j * 4 + 2) & 0xFF) << 8) |
			           (buffer.get(j * 4 + 3) & 0xFF);
		}

		var a = h[0];
		var b = h[1];
		var c = h[2];
		var d = h[3];
		var e = h[4];

		for (j in 0...80) {
			if (j >= 16) {
				w[j] = rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
			}
			var t = rol(a, 5) + ft(j, b, c, d) + e + w[j] + kt(j);
			e = d;
			d = c;
			c = rol(b, 30);
			b = a;
			a = t;
		}

		h[0] += a;
		h[1] += b;
		h[2] += c;
		h[3] += d;
		h[4] += e;
	}

	/**
		Bitwise rotate a 32-bit number to the left
	**/
	inline function rol(num:Int, cnt:Int):Int {
		return (num << cnt) | (num >>> (32 - cnt));
	}

	/**
		Perform the appropriate triplet combination function for the current iteration
	**/
	function ft(t:Int, b:Int, c:Int, d:Int):Int {
		if (t < 20)
			return (b & c) | ((~b) & d);
		if (t < 40)
			return b ^ c ^ d;
		if (t < 60)
			return (b & c) | (b & d) | (c & d);
		return b ^ c ^ d;
	}

	/**
		Determine the appropriate additive constant for the current iteration
	**/
	function kt(t:Int):Int {
		if (t < 20)
			return 0x5A827999;
		if (t < 40)
			return 0x6ED9EBA1;
		if (t < 60)
			return 0x8F1BBCDC;
		return 0xCA62C1D6;
	}
	#end
}
