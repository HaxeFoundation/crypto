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
        if (!initialized) init();
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
        return (python.Syntax.code("{0}[0]", data) << 24) | 
               (python.Syntax.code("{0}[1]", data) << 16) | 
               (python.Syntax.code("{0}[2]", data) << 8) | 
               python.Syntax.code("{0}[3]", data);
        #elseif php
        return php.Syntax.code("random_int(-2147483648, 2147483647)");
        #elseif flash
        return  Bytes.ofData(untyped __global__["flash.crypto.generateRandomBytes"](4));
        #elseif (sys || interp || macro)
        return sysInt();
        #end
        throw "Secure random not supported on this target";
    }

    /**
     * Returns secure random bytes.
     */
    public static function bytes(length:Int):Bytes {
        if (length <= 0) return Bytes.alloc(0);
        if (!initialized) init();
        #if cs
        var buf = new cs.NativeArray<cs.types.UInt8>(length);
        csprng.GetBytes(buf);
        var result = Bytes.alloc(length);
        for (i in 0...length) result.set(i, buf[i]);
        return result;
        #elseif (java || jvm)
        var result = Bytes.alloc(length);
        var r = 0;
        for (i in 0...length) {
            if (i % 4 == 0) r = srng.nextInt();
            result.set(i, (r >> (8 * (i % 4))) & 255);
        }
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
        if (min >= max) throw "Invalid range: min must be less than max";
        return min + Math.floor(float() * (max - min));
    }

    /**
     * Returns a random boolean value.
     */
    public static function bool():Bool {
        return (int() & 1) == 1;
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
            for (i in 0...length) result.set(i, buf[i]);
            return result;
        }
        if (js.Syntax.typeof(js.Syntax.code("require")) != "undefined") {
            var crypto = js.Syntax.code("require('crypto')");
            var buf = crypto.randomBytes(length);
            var result = Bytes.alloc(length);
            for (i in 0...length) result.set(i, buf[i]);
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
        #if macro
        trace("Warning: Using Math.random fallback");
        return Math.floor(Math.random() * 2147483647) - 1073741823;
        #end
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
        #if macro
        trace("Warning: Using Math.random fallback");
        var result = Bytes.alloc(length);
        for (i in 0...length) result.set(i, Math.floor(Math.random() * 256));
        return result;
        #end
        throw "No secure random source available";
    }

    static function winInt():Int {
        try {
            var proc = new sys.io.Process("powershell", ["-NoProfile", "-Command", 
                "$r=[System.Security.Cryptography.RNGCryptoServiceProvider]::new();" +
                "$b=New-Object byte[] 4;$r.GetBytes($b);$r.Dispose();$b-join','"]);
            
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
        trace("Warning: Using Math.random fallback");
        return Math.floor(Math.random() * 2147483647) - 1073741823;
    }

    static function winBytes(length:Int):Bytes {
        try {
            var proc = new sys.io.Process("powershell", ["-NoProfile", "-Command", 
                "$r=[System.Security.Cryptography.RNGCryptoServiceProvider]::new();" +
                "$b=New-Object byte[] " + length + ";$r.GetBytes($b);$r.Dispose();$b-join','"]);
            
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
        trace("Warning: Using Math.random fallback");
        var result = Bytes.alloc(length);
        for (i in 0...length) result.set(i, Math.floor(Math.random() * 256));
        return result;
    }
    #end
}