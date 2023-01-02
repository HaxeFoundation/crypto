package haxe.crypto;

import haxe.Int64;
import haxe.io.Bytes;

class Murmur1 {
	inline static final m:Int32 = 0xc6a4a793;

	public function new() {}

	public static function hash(b:haxe.io.Bytes, seed:Int = 0):UInt {
		var length = b.length;
		var h:Int32 = seed ^ (length * m);
		var quarterLength = length >> 2;
		for (i in 0...quarterLength) {
			var pos = i << 2;
			var k:Int32 = b.get(pos);
			k |= b.get(pos + 1) << 8;
			k |= b.get(pos + 2) << 16;
			k |= b.get(pos + 3) << 24;
			h += k;
			h *= m;
			h ^= h >>> 16;
		}
		var offset = quarterLength << 2;
		var rlen = length & 3;
		if (rlen == 3) {
			h += b.get(offset + 2) << 16;
		}
		if (rlen >= 2) {
			h += b.get(offset + 1) << 8;
		}
		if (rlen >= 1) {
			h += b.get(offset);
			h *= m;
			h ^= (h >>> 16);
		}
		h *= m;
		h ^= h >>> 10;
		h *= m;
		h ^= h >>> 17;
		return h;
	}
}