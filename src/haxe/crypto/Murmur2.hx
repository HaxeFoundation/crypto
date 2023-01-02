package haxe.crypto;

import haxe.Int64;

class Murmur2 {
	inline static final m:Int32 = 0x5bd1e995;
	inline static final r:Int = 24;
	static final m64:Int64 = Int64.make(0xc6a4a793, 0x5bd1e995);
	inline static final r64:Int = 47;

	public function new() {}

	public static function hash(b:haxe.io.Bytes, seed:Int = 0):UInt 
    {
		var length = b.length;
		var h:Int32 = seed ^ length;
		var length4 = length >>> 2;
		for (i in 0...length4) {
			var i4 = i << 2;
			var k = b.get(i4);
			k |= (b.get(i4 + 1) << 8);
			k |= (b.get(i4 + 2) << 16);
			k |= (b.get(i4 + 3) << 24);
			k *= m;
			k ^= k >>> r;
			k *= m;
			h *= m;
			h ^= k;
		}
		var offset:Int = length4 << 2;
		var lastBytes:Int = length & 3;
		if (lastBytes == 3) {
			h ^= b.get(offset + 2) << 16;
		}
		if (lastBytes >= 2) {
			h ^= b.get(offset + 1) << 8;
		}
		if (lastBytes >= 1) {
			h ^= b.get(offset);
			h *= m;
		}
		h ^= h >>> 13;
		h *= m;
		h ^= h >>> 15;
		return h;
	}

	public static function hash64(b:haxe.io.Bytes, seed:Int = 0):String 
    {
		var length = b.length;
		var h:Int64 = seed ^ (length * m64);
		var length8 = length >> 3;
		for (i in 0...length8) {
			var i8:Int = i << 3;
			var low:Int32 = b.get(i8) + (b.get(i8 + 1) << 8) + (b.get(i8 + 2) << 16) + (b.get(i8 + 3) << 24);
			var high:Int32 = (b.get(i8 + 4)) + (b.get(i8 + 5) << 8) + (b.get(i8 + 6) << 16) + (b.get(i8 + 7) << 24);
			var k:Int64 = Int64.make(high, low);
			k *= m64;
			k ^= k >>> r64;
			k *= m64;
			h ^= k;
			h *= m64;
		}

		var offset:Int = length8 << 3;
		var lastBytes:Int = length & 7;
		if (lastBytes == 7) {
			h ^= Int64.shl(b.get(offset + 6), 48);
		}
		if (lastBytes >= 6) {
			// h ^= b.get(offset+5)<<40;   // 100<<40 return 0
			h ^= Int64.shl(b.get(offset + 5), 40);
		}
		if (lastBytes >= 5) {
			h ^= Int64.shl(b.get(offset + 4), 32);
		}

		if (lastBytes >= 4) {
			h ^= Int64.shl(b.get(offset + 3), 24);
		}

		if (lastBytes >= 3) {
			h ^= Int64.shl(b.get(offset + 2), 16);
		}

		if (lastBytes >= 2) {
			h ^= Int64.shl(b.get(offset + 1), 8);
		}

		if (lastBytes >= 1) {
			h ^= b.get(offset);
			h *= m64;
		}
		h ^= h >>> r64;
		h *= m64;
		h ^= h >>> r64;

		var result:String = StringTools.hex(h.high, 8) + StringTools.hex(h.low, 8);
		return result;
	}
}
