package haxe.crypto.random;

import haxe.io.Bytes;

/**
 * Cross-platform cryptographically secure random number generator
 */
class SecureRandom {
	static inline var URANDOM = "/dev/urandom";
	static inline var MAX_UINT32 = 4294967296.0;

	static var initialized = false;

	#if cs
	static var csprng:cs.system.security.cryptography.RandomNumberGenerator;
	#elseif (java || jvm)
	static var srng:java.security.SecureRandom;
	#end

	static function init() {
		#if cs
		csprng = cs.system.security.cryptography.RandomNumberGenerator.Create();
		#elseif (java || jvm)
		srng = new java.security.SecureRandom();
		#end
		initialized = true;
	}

	/**
	 * Returns a secure random 32-bit signed integer.
	 */
	public static function int():Int {
		if (!initialized)
			init();
		#if cs
		var buf = new cs.NativeArray<cs.types.UInt8>(4);
		csprng.GetBytes(buf);
		return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
		#elseif (java || jvm)
		return srng.nextInt();
		#elseif js
		return jsInt();
		#elseif python
		var data = python.Syntax.code("__import__('os').urandom(4)");
		return python.Syntax.code("__import__('struct').unpack('>i', {0})[0]", data);
		#elseif php
		return php.Syntax.code("random_int(-2147483648, 2147483647)");
		#elseif flash
		var buf:Bytes = Bytes.ofData(untyped __global__["flash.crypto.generateRandomBytes"](4));
		return (buf.get(0) << 24) | (buf.get(1) << 16) | (buf.get(2) << 8) | buf.get(3);
		#elseif (sys || interp || macro)
		return sysInt();
		#end
		throw "Secure random not supported on this target";
	}

	/**
	 * Returns secure random bytes.
	 */
	public static function bytes(length:Int):Bytes {
		if (length <= 0)
			return Bytes.alloc(0);
		if (!initialized)
			init();
		#if cs
		var buf = new cs.NativeArray<cs.types.UInt8>(length);
		csprng.GetBytes(buf);
		var result = Bytes.alloc(length);
		for (i in 0...length)
			result.set(i, buf[i]);
		return result;
		#elseif (java || jvm)
		var result = Bytes.alloc(length);
		srng.nextBytes(cast result.getData());
		return result;
		#elseif js
		return jsBytes(length);
		#elseif python
		var data = python.Syntax.code("__import__('os').urandom({0})", length);
		var result = Bytes.alloc(length);
		for (i in 0...length) {
			result.set(i, python.Syntax.code("{0}[{1}]", data, i));
		}
		return result;
		#elseif php
		return Bytes.ofString(php.Syntax.code("random_bytes({0})", length));
		#elseif flash
		return Bytes.ofData(untyped __global__["flash.crypto.generateRandomBytes"](length));
		#elseif (sys || interp || macro)
		return sysBytes(length);
		#end
		throw "Secure random not supported on this target";
	}

	/**
	 * Returns a random float between 0.0 (inclusive) and 1.0 (exclusive)
	 */
	public static function float():Float {
		var i = int();
		var unsigned:Float = i < 0 ? i + MAX_UINT32 : i;
		return unsigned / MAX_UINT32;
	}

	/**
	 * Returns a random integer within the specified range
	 */
	public static function range(min:Int, max:Int):Int {
		if (min >= max)
			throw "Invalid range: min must be less than max";
		return min + Math.floor(float() * (max - min));
	}

	/**
	 * Returns a random boolean value.
	 */
	public static function bool():Bool {
		return (int() & 1) == 1;
	}

	/**
	 * Fill an existing Bytes object with secure random data
	 * @param dest The Bytes to fill
	 * @param offset Starting offset
	 * @param length Number of bytes to fill (default: entire length)
	 */
	public static function fillBytes(dest:Bytes, offset:Int = 0, length:Int = -1):Void {
		if (length == -1) {
			length = dest.length - offset;
		}
		if (offset < 0 || length < 0 || offset + length > dest.length) {
			throw "Invalid offset or length";
		}
		dest.blit(offset, bytes(length), 0, length);
	}

	/**
	 * Secure random string of specified length with given character set
	 * @param length Length of the string
	 * @param charset Character set to use (default: alphanumeric)
	 * @return Secure random string
	 */
	public static function string(length:Int, charset:String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"):String {
		var result = new StringBuf();
		var charsetLength = charset.length;
		var randomBytes = bytes(length);
		var rnd:Float = 0;
		for (i in 0...randomBytes.length) {
			var index = Std.int(randomBytes.get(i) * charsetLength / 256);
			result.add(charset.charAt(index));
		}
		return result.toString();
	}

	/**
	 * Secure random hexadecimal string
	 * @param length Number of hex characters to generate
	 * @return Random hex string
	 */
	public static function hex(length:Int):String {
		return string(length, "0123456789ABCDEF");
	}

	#if js
	static function jsInt():Int {
		if (js.Syntax.typeof(js.Browser.window) != "undefined") {
			var buf = new js.lib.Int32Array(1);
			js.Browser.window.crypto.getRandomValues(buf);
			return buf[0];
		}
		if (js.Syntax.typeof(js.Syntax.code("require")) != "undefined") {
			var crypto = js.Syntax.code("require('crypto')");
			var buf = crypto.randomBytes(4);
			return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
		}
		throw "No secure random source available";
	}

	static function jsBytes(length:Int):Bytes {
		if (js.Syntax.typeof(js.Browser.window) != "undefined") {
			var buf = new js.lib.Uint8Array(length);
			js.Browser.window.crypto.getRandomValues(buf);
			var result = Bytes.alloc(length);
			for (i in 0...length)
				result.set(i, buf[i]);
			return result;
		}
		if (js.Syntax.typeof(js.Syntax.code("require")) != "undefined") {
			var crypto = js.Syntax.code("require('crypto')");
			var buf = crypto.randomBytes(length);
			var result = Bytes.alloc(length);
			for (i in 0...length)
				result.set(i, buf[i]);
			return result;
		}
		throw "No secure random source available";
	}
	#end

	#if (sys || interp || macro)
	static function sysInt():Int {
		if (sys.FileSystem.exists(URANDOM)) {
			var file = sys.io.File.read(URANDOM);
			var result = file.readInt32();
			file.close();
			return result;
		}
		if (Sys.systemName() == "Windows") {
			return winInt();
		}
		throw "No secure random source available";
	}

	static function sysBytes(length:Int):Bytes {
		if (sys.FileSystem.exists(URANDOM)) {
			var file = sys.io.File.read(URANDOM);
			var result = file.read(length);
			file.close();
			return result;
		}
		if (Sys.systemName() == "Windows") {
			return winBytes(length);
		}
		throw "No secure random source available";
	}

	static function winInt():Int {
		try {
			var proc = new sys.io.Process("powershell", [
				"-NoProfile",
				"-Command",
				"$r=[System.Security.Cryptography.RNGCryptoServiceProvider]::new();" + "$b=New-Object byte[] 4;$r.GetBytes($b);$r.Dispose();$b-join','"
			]);

			var output = StringTools.trim(proc.stdout.readAll().toString());
			var code = proc.exitCode();
			proc.close();
			if (code == 0 && output.length > 0) {
				var parts = output.split(",");
				if (parts.length >= 4) {
					var bytes = [for (i in 0...4) Std.parseInt(parts[i])];
					if (bytes.indexOf(null) == -1) {
						return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
					}
				}
			}
		} catch (_) {}
		throw "No secure random source available";
	}

	static function winBytes(length:Int):Bytes {
		try {
			var proc = new sys.io.Process("powershell", ["-NoProfile",
				"-Command",
				"$r=[System.Security.Cryptography.RNGCryptoServiceProvider]::new();"
				+ "$b=New-Object byte[] "
				+ length
				+ ";$r.GetBytes($b);$r.Dispose();$b-join','"]);

			var output = StringTools.trim(proc.stdout.readAll().toString());
			var code = proc.exitCode();
			proc.close();
			if (code == 0 && output.length > 0) {
				var parts = output.split(",");
				var result = Bytes.alloc(length);
				for (i in 0...Math.floor(Math.min(length, parts.length))) {
					var val = Std.parseInt(parts[i]);
					result.set(i, val != null ? val : Math.floor(Math.random() * 256));
				}
				return result;
			}
		} catch (_) {}
		throw "No secure random source available";
	}
	#end
}
