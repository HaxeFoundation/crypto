/*
 * Copyright (C)2005-2023 Haxe Foundation
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

/**
	Hash methods for Hmac calculation.
 */
enum HashMethod {
	MD5;
	SHA1;
	SHA224;
	SHA256;
	SHA384;
	SHA512;
	RIPEMD160;
}

/**
	Calculates a Hmac of the given Bytes using a HashMethod.
 */
class Hmac {
	var method:HashMethod;
	var blockSize:Int;
	var length:Int;
	
	public static var debug:Bool = false;

	public function new(hashMethod:HashMethod) {
		if (hashMethod != null)
			init(hashMethod);
	}

	public function getSize():Int {
		return length;
	}

	public function init(hashMethod:HashMethod):Void {
		method = hashMethod;
		blockSize = switch (hashMethod) {
			case MD5, SHA1, SHA224, SHA256, RIPEMD160: 64;
			case SHA384, SHA512: 128;
		}
		length = switch (hashMethod) {
			case MD5: 16;
			case SHA1: 20;
			case SHA224: 28;
			case SHA256: 32;
			case SHA384: 48;
			case SHA512: 64;
			case RIPEMD160: 20;
		}
	}

	inline function doHash(b:haxe.io.Bytes):haxe.io.Bytes {
		return switch (method) {
			case MD5: Md5.make(b);
			case SHA1: Sha1.make(b);
			case SHA224: Sha224.make(b);
			case SHA256: Sha256.make(b);
			case SHA384: Sha384.make(b);
			case SHA512: Sha512.make(b);
			case RIPEMD160: Ripemd160.make(b);
		}
	}

	function nullPad(s:haxe.io.Bytes, chunkLen:Int):haxe.io.Bytes {
		var r = chunkLen - (s.length % chunkLen);
		if (r == chunkLen && s.length != 0)
			return s;
		var sb = Bytes.alloc(s.length + r);
		new haxe.io.BytesBuffer();
		var pos = s.length;
		sb.blit(0, s, 0, pos);
		for (x in 0...r)
			sb.set(pos + x, 0);
		return sb;
	}

	public function make(key:haxe.io.Bytes, msg:haxe.io.Bytes):haxe.io.Bytes {
		if (key.length > blockSize) {
			key = doHash(key);
		}
		key = nullPad(key, blockSize);
		if (debug) {
			trace("key:  " + key.toHex());
			trace("msg:  " + msg.toHex());
		}
		var Ki = Bytes.alloc(key.length + msg.length);
		var Ko = Bytes.alloc(key.length + length);
		for (i in 0...key.length) {
			Ko.set(i, key.get(i) ^ 0x5c);
			Ki.set(i, key.get(i) ^ 0x36);
		}
		// hash(Ko + hash(Ki + message))
		if (debug) {
			trace("1) " + Ki.toHex());
			trace("1) " + Ko.toHex());
		}
		Ki.blit(key.length, msg, 0, msg.length);
		if (debug) {
			trace("2) " + Ki.toHex());
		}
		Ko.blit(key.length, doHash(Ki), 0, length);
		if (debug) {
			trace("2) " + Ko.toHex());
			debug = false;
		}
		return doHash(Ko);
	}
}
