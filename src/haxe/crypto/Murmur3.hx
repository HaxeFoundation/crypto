package haxe.crypto;

import haxe.io.Encoding;
import haxe.io.Bytes;
import haxe.Int64;

class Murmur3 {
	private static final C1_32:Int = 0xcc9e2d51;
	private static final C2_32:Int = 0x1b873593;
	private static final C1_128_x64:Int64 = Int64.make(0x87c37b91, 0x114253d5);
	private static final C2_128_x64:Int64 = Int64.make(0x4cf5ad43, 0x2745937f);
	private static final C1_128_x86:Int = 0x239b961b;
	private static final C2_128_x86:Int = 0xab0e9789;
	private static final C3_128_x86:Int = 0x38b34ae5;
	private static final C4_128_x86:Int = 0xa1e38b93;
	private static final F64_C1:Int64 = Int64.make(0xff51afd7, 0xed558ccd);
	private static final F64_C2:Int64 = Int64.make(0xc4ceb9fe, 0x1a85ec53);

	private var lastBytes:Int = 0;
	private var k1:Int32 = 0;
	private var len:Int = 0;
	private var h1:UInt = 0;
	private var seed:Int = 0;

	public function new(seed:Int = 0) {
		this.reset(seed);
	}

	public function reset(seed:Int=0):Murmur3 
    {
		this.seed = seed;
		h1 = seed;
		lastBytes = k1 = len = 0;
		return this;
	}

	public function addString(v:String, ?encoding:Encoding):Murmur3 
    {
		var b = Bytes.ofString(v, encoding);
		return add(b);
	}

	public function add(b:Bytes):Murmur3 
    {
		var length = b.length;
		this.len += length;
		var k = this.k1;
		var h = 0;
		var pos:Int = 0;
		if (lastBytes == 0) {
			k ^= (length > 0) ? b.get(pos++) : 0;
		}
		if (lastBytes <= 1) {
			k ^= (length > pos) ? (b.get(pos++) << 8) : 0;
		}
		if (lastBytes <= 2) {
			k ^= (length > pos) ? (b.get(pos++) << 16) : 0;
		}
		if (lastBytes <= 3) {
			k ^= (length > pos) ? (b.get(pos) << 24) : 0;
			k ^= (length > pos) ? (b.get(pos++) >>> 8) : 0;
		}
		lastBytes = (length + lastBytes) & 3;
		length -= lastBytes;
		if (length > 0) {
			h = this.h1;

			k *= C1_32;
			k = rotl32(k, 15);
			k *= C2_32;

			h ^= k;
			h = rotl32(h, 13);
			h = h * 5 + 0xe6546b64;

			while (pos < length) {
				k = b.get(pos++);
				k |= b.get(pos++) << 8;
				k |= b.get(pos++) << 16;
				k |= b.get(pos++) << 24;

				k *= C1_32;
				k = rotl32(k, 15);
				k *= C2_32;

				h ^= k;
				h = rotl32(h, 13);
				h = h * 5 + 0xe6546b64;
			}

			k = 0;
			if (lastBytes == 3) {
				k ^= (b.get(pos + 2) << 16);
			}
			if (lastBytes >= 2) {
				k ^= (b.get(pos + 1) << 8);
			}
			if (lastBytes >= 1) {
				k ^= b.get(pos);
			}
			this.h1 = h;
		}

		this.k1 = k;
		return this;
	}

	public function result():UInt 
    {
		var k = k1;
		var h = h1;
		if (k > 0) {
			k *= C1_32;
			k = rotl32(k, 15);
			k *= C2_32;
			h ^= k;
		}
		h ^= this.len;
		h = fmix32(h);
		return h;
	}

	public static function hash(b:Bytes, seed:Int = 0):UInt 
    {
		var length = b.length;
		var nblocks = length >> 2;
		var h:UInt = seed;
		for (i in 0...nblocks) {
			var pos:Int = i << 2;
			var k:Int32 = b.get(pos);
			k |= b.get(pos + 1) << 8;
			k |= b.get(pos + 2) << 16;
			k |= b.get(pos + 3) << 24;
			k *= C1_32;
			k = rotl32(k, 15);
			k *= C2_32;
			h ^= k;
			h = rotl32(h, 13);
			h = h * 5 + 0xe6546b64;
		}
		var offset = nblocks << 2;
		var k:Int = 0;
		var lastBytes:Int = length & 3;
		if (lastBytes == 3) {
			k ^= b.get(offset + 2) << 16;
		}
		if (lastBytes >= 2) {
			k ^= b.get(offset + 1) << 8;
		}
		if (lastBytes >= 1) {
			k ^= b.get(offset);
			k *= C1_32;
			k = rotl32(k, 15);
			k *= C2_32;
			h ^= k;
		}
		h ^= length;
		h = fmix32(h);
		return h;
	}

	public static function hash128(b:haxe.io.Bytes, ?seed:Int64):String 
    {
		if (seed == null)
			seed = 0;
		var length = b.length;
		var h1 = seed;
		var h2 = seed;
		var blen:Int = b.length;
		while (blen >= 16) {
			var k1 = b.getInt64(length - blen);
			var k2 = b.getInt64(length - blen + 8);
			h1 ^= mixK1(k1);

			h1 = rotl64(h1, 27);
			h1 += h2;
			h1 = h1 * 5 + 0x52dce729;

			h2 ^= mixK2(k2);

			h2 = rotl64(h2, 31);
			h2 += h1;
			h2 = h2 * 5 + 0x38495ab5;
			blen -= 16;
		}

		if (blen > 0) {
			var k1:Int64 = Int64.ofInt(0);
			var k2:Int64 = Int64.ofInt(0);
			var mpos:Int = length - blen;
			if (blen >= 8) {
				if (blen == 15) {
					k2 ^= Int64.shl(b.get(mpos + 14), 48);
				}
				if (blen >= 14) {
					k2 ^= Int64.shl(b.get(mpos + 13), 40);
				}
				if (blen >= 13) {
					k2 ^= Int64.shl(b.get(mpos + 12), 32);
				}
				if (blen >= 12) {
					k2 ^= Int64.shl(b.get(mpos + 11), 24);
				}
				if (blen >= 11) {
					k2 ^= Int64.shl(b.get(mpos + 10), 16);
				}
				if (blen >= 10) {
					k2 ^= Int64.shl(b.get(mpos + 9), 8);
				}
				if (blen >= 9) {
					k2 ^= b.get(mpos + 8);
				}

				k1 ^= b.getInt64(mpos);
			} else {
				if (blen == 7) {
					k1 ^= Int64.shl(b.get(mpos + 6), 48);
				}
				if (blen >= 6) {
					k1 ^= Int64.shl(b.get(mpos + 5), 40);
				}
				if (blen >= 5) {
					k1 ^= Int64.shl(b.get(mpos + 4), 32);
				}
				if (blen >= 4) {
					k1 ^= Int64.shl(b.get(mpos + 3), 24);
				}
				if (blen >= 3) {
					k1 ^= Int64.shl(b.get(mpos + 2), 16);
				}
				if (blen >= 2) {
					k1 ^= Int64.shl(b.get(mpos + 1), 8);
				}
				if (blen >= 1) {
					k1 ^= b.get(mpos);
				}
			}
			h1 ^= mixK1(k1);
			h2 ^= mixK2(k2);
		}

		h1 ^= length;
		h2 ^= length;

		h1 += h2;
		h2 += h1;

		h1 = fmix64(h1);
		h2 = fmix64(h2);

		h1 += h2;
		h2 += h1;

		var result:String = StringTools.hex(h1.high, 8) + StringTools.hex(h1.low, 8) + StringTools.hex(h2.high, 8) + StringTools.hex(h2.low, 8);
		return result;
	}

	public static function hash128_x86(b:haxe.io.Bytes, seed:Int = 0):String 
    {
		var length = b.length;
		var h1 = seed;
		var h2 = seed;
		var h3 = seed;
		var h4 = seed;

		var blen:Int = b.length;
		while (blen >= 16) {
			var pos = length - blen;
			var k1:Int32 = b.get(pos) | (b.get(pos + 1) << 8) | (b.get(pos + 2) << 16) | (b.get(pos + 3) << 24);
			var k2:Int32 = b.get(pos + 4) | (b.get(pos + 5) << 8) | (b.get(pos + 6) << 16) | (b.get(pos + 7) << 24);
			var k3:Int32 = b.get(pos + 8) | (b.get(pos + 9) << 8) | (b.get(pos + 10) << 16) | (b.get(pos + 11) << 24);
			var k4:Int32 = b.get(pos + 12) | (b.get(pos + 13) << 8) | (b.get(pos + 14) << 16) | (b.get(pos + 15) << 24);

			k1 = k1 * C1_128_x86;
			k1 = rotl32(k1, 15);
			k1 = k1 * C2_128_x86;
			h1 ^= k1;

			h1 = rotl32(h1, 19);
			h1 += h2;
			h1 = h1 * 5 + 0x561ccd1b;

			k2 = k2 * C2_128_x86;
			k2 = rotl32(k2, 16);
			k2 = k2 * C3_128_x86;
			h2 ^= k2;

			h2 = rotl32(h2, 17);
			h2 += h3;
			h2 = h2 * 5 + 0x0bcaa747;

			k3 = k3 * C3_128_x86;
			k3 = rotl32(k3, 17);
			k3 = k3 * C4_128_x86;
			h3 ^= k3;

			h3 = rotl32(h3, 15);
			h3 += h4;
			h3 = h3 * 5 + 0x96cd1c35;

			k4 = k4 * C4_128_x86;
			k4 = rotl32(k4, 18);
			k4 = k4 * C1_128_x86;
			h4 ^= k4;

			h4 = rotl32(h4, 13);
			h4 += h1;
			h4 = h4 * 5 + 0x32ac3b17;

			blen -= 16;
		}

		if (blen > 0) {
			var k1 = 0, k2 = 0, k3 = 0, k4 = 0;
			var mpos:Int = length - blen;
			if (blen == 15) {
				k4 ^= b.get(mpos + 14) << 16;
			}
			if (blen >= 14) {
				k4 ^= b.get(mpos + 13) << 8;
			}
			if (blen >= 13) {
				k4 ^= b.get(mpos + 12);
				k4 = k4 * C4_128_x86;
				k4 = rotl32(k4, 18);
				k4 = k4 * C1_128_x86;
				h4 ^= k4;
			}
			if (blen >= 12) {
				k3 ^= b.get(mpos + 11) << 24;
			}
			if (blen >= 11) {
				k3 ^= b.get(mpos + 10) << 16;
			}
			if (blen >= 10) {
				k3 ^= b.get(mpos + 9) << 8;
			}
			if (blen >= 9) {
				k3 ^= b.get(mpos + 8);
				k3 = k3 * C3_128_x86;
				k3 = rotl32(k3, 17);
				k3 = k3 * C4_128_x86;
				h3 ^= k3;
			}

			if (blen >= 8) {
				k2 ^= b.get(mpos + 7) << 24;
			}
			if (blen >= 7) {
				k2 ^= b.get(mpos + 6) << 16;
			}
			if (blen >= 6) {
				k2 ^= b.get(mpos + 5) << 8;
			}
			if (blen >= 5) {
				k2 ^= b.get(mpos + 4);
				k2 = k2 * C2_128_x86;
				k2 = rotl32(k2, 16);
				k2 = k2 * C3_128_x86;
				h2 ^= k2;
			}
			if (blen >= 4) {
				k1 ^= b.get(mpos + 3) << 24;
			}
			if (blen >= 3) {
				k1 ^= b.get(mpos + 2) << 16;
			}

			if (blen >= 2) {
				k1 ^= b.get(mpos + 1) << 8;
			}
			if (blen >= 1) {
				k1 ^= b.get(mpos);
				k1 = k1 * C1_128_x86;
				k1 = rotl32(k1, 15);
				k1 = k1 * C2_128_x86;
				h1 ^= k1;
			}
		}

		h1 ^= length;
		h2 ^= length;
		h3 ^= length;
		h4 ^= length;

		h1 += h2;
		h1 += h3;
		h1 += h4;
		h2 += h1;
		h3 += h1;
		h4 += h1;

		h1 = fmix32(h1);
		h2 = fmix32(h2);
		h3 = fmix32(h3);
		h4 = fmix32(h4);

		h1 += h2;
		h1 += h3;
		h1 += h4;
		h2 += h1;
		h3 += h1;
		h4 += h1;

		var result:String = StringTools.hex(h1, 8) + StringTools.hex(h2, 8) + StringTools.hex(h3, 8) + StringTools.hex(h4, 8);
		return result;
	}

	private static inline function rotl32(k:Int32, shift:Int):Int32 {
		return ((k << shift) | (k >>> (32 - shift)));
	}

	private static inline function fmix32(k:UInt):UInt 
    {
		k ^= (k >> 16);
		k = (k * 0x85ebca6b);
		k ^= (k >> 13);
		k = (k * 0xc2b2ae35);
		k ^= (k >> 16);
		return k;
	}

	public static function rotl64(i:Int64, distance:Int):Int64 {
		return Int64.or((Int64.shl(i, distance)), (i >>> -distance));
	}

	private static inline function fmix64(k:Int64):Int64 
    {
		k ^= k >>> 33;
		k = Int64.mul(k, F64_C1);
		k ^= k >>> 33;
		k = Int64.mul(k, F64_C2);
		k ^= k >>> 33;
		return k;
	}

	private static inline function mixK1(k1:Int64):Int64 
    {
		k1 *= C1_128_x64;
		k1 = rotl64(k1, 31);
		k1 *= C2_128_x64;
		return k1;
	}

	private static inline function mixK2(k2:Int64):Int64 
    {
		k2 *= C2_128_x64;
		k2 = rotl64(k2, 33);
		k2 *= C1_128_x64;
		return k2;
	}
}