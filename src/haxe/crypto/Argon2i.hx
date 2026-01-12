package haxe.crypto;

import haxe.io.Bytes;

class Argon2i {
    public static function hash(password:Bytes, salt:Bytes, timeCost:Int = 3, memoryCostKiB:Int = 65536, parallelism:Int = 4, hashLength:Int = 32, ?secret:Bytes, ?associatedData:Bytes):Bytes {
        return Argon2.hash(password, salt, Argon2.TYPE_I, timeCost, memoryCostKiB, parallelism, hashLength, secret, associatedData);
    }
    
    public static function verify(hash:Bytes, password:Bytes, salt:Bytes, timeCost:Int = 3, memoryCostKiB:Int = 32, parallelism:Int = 4, ?secret:Bytes, ?ad:Bytes):Bool {
        var computed = Argon2i.hash(password, salt, timeCost, memoryCostKiB, parallelism, hash.length, secret, ad);
        if (computed.length != hash.length) return false;
        var diff = 0;
        for (i in 0...hash.length) diff |= hash.get(i) ^ computed.get(i);
        return diff == 0;
    }
}