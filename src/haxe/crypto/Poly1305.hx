package haxe.crypto;

import haxe.ds.Vector;
import haxe.io.Bytes;

class Poly1305 {
	static inline var NB:Int = 4;
	static inline var BLOCK_SIZE:Int = 16;

	private var r:Vector<Int64>;
	private var h:Vector<Int64>;
	private var s:Vector<Int64>;
	private var pad:Vector<Int64>;
	private var buffer:Bytes;
	private var blockOffset:Int;
	private var MASK_ZERO:Int64;

	public var nonce(default, set):Bytes;

	function set_nonce(vector) {
		nonce = vector;
		if (nonce == null) {
			nonce = Bytes.alloc(BLOCK_SIZE);
			nonce.fill(0, BLOCK_SIZE, 0x00);
		}
		return nonce;
	}

	public function new(?key:Bytes, ?nonce:Bytes) {
		r = new Vector(5);
		h = new Vector<Int64>(5);
		s = new Vector<Int64>(4);
		pad = new Vector<Int64>(4);
		buffer = Bytes.alloc(BLOCK_SIZE);
		blockOffset = 0;

		MASK_ZERO = Int64.make(0x00000000, 0xFFFFFFFF);

		for (i in 0...5) {
			r[i] = 0;
			h[i] = 0;
		}

		for (i in 0...4) {
			pad[i] = 0;
			s[i] = 0;
		}

		if (key != null)
			init(key, nonce);
	}

	public function getBlockSize():Int {
		return BLOCK_SIZE;
	}

	public function init(key:Bytes, ?nonce:Bytes):Void {
		if (key.length != 32)
			throw "Key must be 32 bytes";
		if (nonce != null && nonce.length != BLOCK_SIZE)
			throw "Nonce must be exactly 16 bytes";
		this.nonce = nonce;
		r[0] = bytesToInt32(key, 0) & 0x3ffffff;
		r[1] = (bytesToInt32(key, 3) >>> 2) & 0x3ffff03;
		r[2] = (bytesToInt32(key, 6) >>> 4) & 0x3ffc0ff;
		r[3] = (bytesToInt32(key, 9) >>> 6) & 0x3f03fff;
		r[4] = (bytesToInt32(key, 12) >>> 8) & 0x00fffff;

		for (i in 0...4)
			s[i] = r[i + 1] * 5;

		pad[0] = bytesToInt32(key, 16);
		pad[1] = bytesToInt32(key, 20);
		pad[2] = bytesToInt32(key, 24);
		pad[3] = bytesToInt32(key, 28);
	}

	public function update(source:Bytes, offset:Int, len:Int):Void {
		var srcPos:Int = 0;
		while (len > 0) {
			if (blockOffset == BLOCK_SIZE) {
				encryptBlock();
				blockOffset = 0;
			}

			var bytesCopy:Int = (len <= (BLOCK_SIZE - blockOffset)) ? len : (BLOCK_SIZE - blockOffset);
			buffer.blit(blockOffset, source, srcPos + offset, bytesCopy);
			len -= bytesCopy;
			blockOffset += bytesCopy;
			srcPos += bytesCopy;
		}
	}

	public function finish(offset:Int = 0):Bytes {
		if (blockOffset > 0) {
			encryptBlock();
		}

		h[1] += (h[0] >>> 26);
		h[0] &= 0x3ffffff;
		h[2] += (h[1] >>> 26);
		h[1] &= 0x3ffffff;
		h[3] += (h[2] >>> 26);
		h[2] &= 0x3ffffff;
		h[4] += (h[3] >>> 26);
		h[3] &= 0x3ffffff;
		h[0] += (h[4] >>> 26) * 5;
		h[4] &= 0x3ffffff;
		h[1] += (h[0] >>> 26);
		h[0] &= 0x3ffffff;

		var c:Int;

		var g0:Int = h[0].low + 5;
		c = g0 >>> 26;
		g0 &= 0x3ffffff;
		var g1:Int = h[1].low + c;
		c = g1 >>> 26;
		g1 &= 0x3ffffff;
		var g2:Int = h[2].low + c;
		c = g2 >>> 26;
		g2 &= 0x3ffffff;
		var g3:Int = h[3].low + c;
		c = g3 >>> 26;
		g3 &= 0x3ffffff;
		var g4:Int = h[4].low + c - (1 << 26);

		c = (g4 >>> 31) - 1;
		var mask:Int = ~c;
		h[0] = (h[0] & mask) | (g0 & c);
		h[1] = (h[1] & mask) | (g1 & c);
		h[2] = (h[2] & mask) | (g2 & c);
		h[3] = (h[3] & mask) | (g3 & c);
		h[4] = (h[4] & mask) | (g4 & c);

		h[0] = ((h[0].low) | (h[1].low << 26));
		h[1] = ((h[1].low >>> 6) | (h[2].low << 20));
		h[2] = ((h[2].low >>> 12) | (h[3].low << 14));
		h[3] = ((h[3].low >>> 18) | (h[4].low << 8));

		h[0] = Int64.and(h[0], MASK_ZERO);
		h[1] = Int64.and(h[1], MASK_ZERO);
		h[2] = Int64.and(h[2], MASK_ZERO);
		h[3] = Int64.and(h[3], MASK_ZERO);

		var f:Int64 = h[0] + Int64.and(pad[0], MASK_ZERO);
		h[0] = f;
		f = h[1] + Int64.and(pad[1], MASK_ZERO) + (f >>> 32);
		h[1] = f;
		f = h[2] + Int64.and(pad[2], MASK_ZERO) + (f >>> 32);
		h[2] = f;
		f = h[3] + Int64.and(pad[3], MASK_ZERO) + (f >>> 32);
		h[3] = f;

		var output = Bytes.alloc(BLOCK_SIZE + offset);

		int32ToBytes(h[0].low, output, offset);
		int32ToBytes(h[1].low, output, offset + 4);
		int32ToBytes(h[2].low, output, offset + 8);
		int32ToBytes(h[3].low, output, offset + 12);

		reset();

		return output;
	}

	public function verify(message:Bytes, key:Bytes, tag:Bytes, ?nonce:Bytes):Bool {
		var out = encode(message, key, nonce);
		return (out.toHex() == tag.toHex());
	}

	public function encode(message:Bytes, key:Bytes, ?nonce:Bytes):Bytes {
		init(key, nonce);
		update(message, 0, message.length);
		var output = this.finish();
		return output;
	}

	public function reset():Void {
		for (i in 0...5)
			h[i] = 0;
		blockOffset = 0;
	}

	private function encryptBlock():Void {
		if (blockOffset < BLOCK_SIZE) {
			buffer.set(blockOffset, 1);
			for (i in (blockOffset + 1)...BLOCK_SIZE) {
				buffer.set(i, 0);
			}
		}

		h[0] += (bytesToInt32(buffer, 0)) & 0x3ffffff;
		h[1] += (bytesToInt32(buffer, 3) >>> 2) & 0x3ffffff;
		h[2] += (bytesToInt32(buffer, 6) >>> 4) & 0x3ffffff;
		h[3] += (bytesToInt32(buffer, 9) >>> 6) & 0x3ffffff;
		h[4] += (bytesToInt32(buffer, 12) >>> 8);

		if (blockOffset == BLOCK_SIZE) {
			h[4] += (1 << 24);
		}

		var t0:Int64 = h[0] * r[0] + h[1] * s[3] + h[2] * s[2] + h[3] * s[1] + h[4] * s[0];
		var t1:Int64 = h[0] * r[1] + h[1] * r[0] + h[2] * s[3] + h[3] * s[2] + h[4] * s[1];
		var t2:Int64 = h[0] * r[2] + h[1] * r[1] + h[2] * r[0] + h[3] * s[3] + h[4] * s[2];
		var t3:Int64 = h[0] * r[3] + h[1] * r[2] + h[2] * r[1] + h[3] * r[0] + h[4] * s[3];
		var t4:Int64 = h[0] * r[4] + h[1] * r[3] + h[2] * r[2] + h[3] * r[1] + h[4] * r[0];

		h[0] = t0.low & 0x3ffffff;
		t1 += (t0 >>> 26);
		h[1] = t1.low & 0x3ffffff;
		t2 += (t1 >>> 26);
		h[2] = t2.low & 0x3ffffff;
		t3 += (t2 >>> 26);
		h[3] = t3.low & 0x3ffffff;
		t4 += (t3 >>> 26);
		h[4] = t4.low & 0x3ffffff;
		h[0] += (t4 >>> 26).low * 5;
		h[1] += (h[0] >>> 26);
		h[0] &= 0x3ffffff;
	}

	private function int32ToBytes(n:Int, bs:Bytes, off:Int):Void {
		bs.set(off, (n));
		bs.set(++off, (n >>> 8));
		bs.set(++off, (n >>> 16));
		bs.set(++off, (n >>> 24));
	}

	private function bytesToInt32(bs:Bytes, off:Int):Int {
		var n:Int = (bs.get(off));
		n |= (bs.get(++off)) << 8;
		n |= (bs.get(++off)) << 16;
		n |= bs.get(++off) << 24;
		return n;
	}
}
