package haxe.crypto;

import haxe.io.Bytes;
import haxe.ds.Vector;

class Blake2b {
    static inline var BLOCK_SIZE = 128;
    static inline var OUT_SIZE = 64;
    
    static var IV:Vector<Int64> = Vector.fromArrayCopy([
        Int64.make(0x6a09e667, 0xf3bcc908), Int64.make(0xbb67ae85, 0x84caa73b),
        Int64.make(0x3c6ef372, 0xfe94f82b), Int64.make(0xa54ff53a, 0x5f1d36f1),
        Int64.make(0x510e527f, 0xade682d1), Int64.make(0x9b05688c, 0x2b3e6c1f),
        Int64.make(0x1f83d9ab, 0xfb41bd6b), Int64.make(0x5be0cd19, 0x137e2179)
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
    
    public var h:Vector<Int64>;
    var t:Vector<Int64>;
    var buf:Bytes;
    var buflen:Int;
    var outlen:Int;
    
    public function new(outlen:Int = 64, key:Bytes = null) {
        if (outlen < 1 || outlen > 64) throw "Invalid output length";
        this.outlen = outlen;
        
        h = new Vector<Int64>(8);
        for (i in 0...8) h[i] = IV[i].copy();
        
        var paramLow = 0x01010000 | (key != null ? (key.length << 8) : 0) | outlen;
        h[0] = Int64.xor(h[0], Int64.make(0, paramLow));
        
        t = new Vector<Int64>(2);
        t[0] = Int64.ofInt(0);
        t[1] = Int64.ofInt(0);
        
        buf = Bytes.alloc(BLOCK_SIZE);
        buflen = 0;
        
        if (key != null && key.length > 0) {
            update(key);
            buflen = BLOCK_SIZE;
        }
    }
    
    static inline function rotr64(x:Int64, n:Int):Int64 {
        return Int64.or(Int64.ushr(x, n), Int64.shl(x, 64 - n));
    }
    
    inline function g(v:Vector<Int64>, a:Int, b:Int, c:Int, d:Int, x:Int64, y:Int64) {
        v[a] = Int64.add(Int64.add(v[a], v[b]), x);
        v[d] = rotr64(Int64.xor(v[d], v[a]), 32);
        v[c] = Int64.add(v[c], v[d]);
        v[b] = rotr64(Int64.xor(v[b], v[c]), 24);
        v[a] = Int64.add(Int64.add(v[a], v[b]), y);
        v[d] = rotr64(Int64.xor(v[d], v[a]), 16);
        v[c] = Int64.add(v[c], v[d]);
        v[b] = rotr64(Int64.xor(v[b], v[c]), 63);
    }
    
    function compress(last:Bool) {
        var v = new Vector<Int64>(16);
        for (i in 0...8) {
            v[i] = h[i].copy();
            v[i + 8] = IV[i].copy();
        }
        
        v[12] = Int64.xor(v[12], t[0]);
        v[13] = Int64.xor(v[13], t[1]);
        if (last) v[14] = Int64.xor(v[14], Int64.make(0xFFFFFFFF, 0xFFFFFFFF));
        
        var m = new Vector<Int64>(16);
        for (i in 0...16) {
            var off = i << 3;
            var lo = buf.get(off) | (buf.get(off + 1) << 8) | 
                     (buf.get(off + 2) << 16) | (buf.get(off + 3) << 24);
            var hi = buf.get(off + 4) | (buf.get(off + 5) << 8) | 
                     (buf.get(off + 6) << 16) | (buf.get(off + 7) << 24);
            m[i] = Int64.make(hi, lo);
        }
        
        for (i in 0...12) {
            var s = SIGMA[i % 10];
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        
        for (i in 0...8) h[i] = Int64.xor(Int64.xor(h[i], v[i]), v[i + 8]);
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
                t[0] = Int64.add(t[0], Int64.ofInt(BLOCK_SIZE));
                if (Int64.compare(t[0], Int64.ofInt(BLOCK_SIZE)) < 0) 
                    t[1] = Int64.add(t[1], Int64.ofInt(1));
                compress(false);
                buflen = 0;
            }
        }
    }
    
    public function digest():Bytes {
        t[0] = Int64.add(t[0], Int64.ofInt(buflen));
        if (Int64.compare(t[0], Int64.ofInt(buflen)) < 0) 
            t[1] = Int64.add(t[1], Int64.ofInt(1));
        
        while (buflen < BLOCK_SIZE) buf.set(buflen++, 0);
        compress(true);
        
        var out = Bytes.alloc(outlen);
        var outPos = 0;
        
        for (i in 0...8) {
            if (outPos >= outlen) break;
            var lo = h[i].low;
            var hi = h[i].high;
            
            if (outPos < outlen) out.set(outPos++, lo & 0xff);
            if (outPos < outlen) out.set(outPos++, (lo >>> 8) & 0xff);
            if (outPos < outlen) out.set(outPos++, (lo >>> 16) & 0xff);
            if (outPos < outlen) out.set(outPos++, (lo >>> 24) & 0xff);
            if (outPos < outlen) out.set(outPos++, hi & 0xff);
            if (outPos < outlen) out.set(outPos++, (hi >>> 8) & 0xff);
            if (outPos < outlen) out.set(outPos++, (hi >>> 16) & 0xff);
            if (outPos < outlen) out.set(outPos++, (hi >>> 24) & 0xff);
        }
        
        return out;
    }
    
    public static function hash(data:Bytes, outlen:Int = 64, key:Bytes = null):Bytes {
        var ctx = new Blake2b(outlen, key);
        ctx.update(data);
        return ctx.digest();
    }
}