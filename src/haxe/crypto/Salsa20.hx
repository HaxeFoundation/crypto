package haxe.crypto;

import haxe.ds.Vector;
import haxe.io.Bytes;
import haxe.Int64;

class Salsa20 {
	static var sigmas_array = [
		0x61707865, 0x3120646E, 0x79622D36, 0x6B206574,
		0x61707865, 0x3320646E, 0x79622D32, 0x6B206574
	];

	private var counter:Int64;

	public var state:Vector<Int> = new Vector<Int>(16);

	static var buffer:Vector<Int> = new Vector<Int>(16);
	static var expandState:Bytes = Bytes.alloc(64);

	private var sigmas:Vector<Int>;
	private var index:Int;
	private var rounds:Int = 20;

	public function new(rounds:Int = 20) {
		sigmas = Vector.fromArrayCopy(sigmas_array);
		counter = Int64.make(0, 0);
		this.rounds = rounds;
	}

	public function init(key:Bytes, nonce:Bytes, ?counter:Int64):Void {
		if (nonce == null || nonce.length != 8)
			throw "Nonce must be exactly 8 bytes";
		if (key == null)
			throw "Key must be 16 or 32 bytes";
		if (key.length != 16 && key.length != 32)
			throw "Wrong key size";

		setConstant(key);
		setNonce(nonce);
		setKey(key);
		reset();
		if (counter != null)
			setCounter(counter);
	}

	private function setConstant(key:Bytes):Void {
		var sigmaOffset:Int = (key.length == 16) ? 0 : 4;
		state[0] = sigmas[sigmaOffset];
		state[5] = sigmas[sigmaOffset + 1];
		state[10] = sigmas[sigmaOffset + 2];
		state[15] = sigmas[sigmaOffset + 3];
	}

	public function setKey(key:Bytes):Void {
		if (key.length == 16) {
			for (i in 0...4) {
				state[i + 1] = state[i + 11] = bytesToInt32(key, i * 4);
			}
		} else {
			for (i in 0...4) {
				state[i + 1] = bytesToInt32(key, i * 4);
				state[i + 11] = bytesToInt32(key, i * 4 + 16);
			}
		}
	}

	public function setNonce(nonce:Bytes):Void {
		state[6] = bytesToInt32(nonce, 0);
		state[7] = bytesToInt32(nonce, 4);
	}

	public function reset():Void {
		index = 0;
		resetCounter();
		generateExpandBlock();
	}

	public function resetCounter():Void {
		counter = 0;
		state[8] = state[9] = 0;
	}

	private function updateCounterState():Void {
		state[8] = counter.low;
		state[9] = counter.high;
	}

	private function increaseCounter(num:Int64):Void {
		counter += num;
		updateCounterState();
	}

	private function decreaseCounter(num:Int64):Void {
		counter -= num;
		updateCounterState();
	}

	public function getPosition():Int64 {
		return counter * 64 + index;
	}

	public function seek(position:Int64):Void {
		reset();
		skip(position);
	}

	public function skip(numBytes:Int64):Void {
		if (numBytes >= 0) {
			var remaining:Int64 = numBytes;
			if (remaining >= 64) {
				var count:Int64 = remaining >> 6;
				increaseCounter(count);
				remaining -= count * 64;
			}
			var previousIndex = index;
			index = Int64.toInt((index + remaining) & 63);
			if (index < previousIndex) {
				increaseCounter(1);
			}
		} else {
			var remaining:Int64 = -numBytes;
			if (remaining >= 64) {
				var count:Int64 = remaining >> 6;
				decreaseCounter(count);
				remaining -= count * 64;
			}
			var i:Int64 = Int64.make(0, 0);
			while (i < remaining) {
				if (index == 0) {
					decreaseCounter(1);
				}
				index = (index - 1) & 63;
				i++;
			}
		}
		generateExpandBlock();
	}

	public function getCounter():Int64 {
		return counter;
	}

	public function setCounter(counter:Int64):Void {
		index = 0;
		this.counter = counter;
		updateCounterState();
		generateExpandBlock();
	}

	public function encrypt(data:Bytes, rounds:Int = 20):Bytes {
		var output = Bytes.alloc(data.length);
		for (i in 0...data.length) {
			output.set(i, expandState.get(index) ^ data.get(i));
			index = (index + 1) & 63;
			if (index == 0) // crypt 64-bit block
			{
				increaseCounter(1);
				generateExpandBlock();
			}
		}
		return output;
	}

	public function decrypt(data:Bytes, rounds:Int = 20):Bytes {
		return encrypt(data, rounds);
	}

	public function generateExpandBlock():Void {
		generateBlock(state, buffer, rounds);

		for (i in 0...16) {
			int32ToBytes(buffer[i], expandState, i << 2);
		}
	}

	public function generateBlock(input:Vector<Int>, output:Vector<Int>, rounds:Int = 20, offset:Int = 0):Void {
		if ((rounds & 1) != 0) {
			throw "Rounds should be a positive, even number";
		}
		if ((offset + 16 > output.length) || input.length != 16) {
			throw "Invalid buffer size";
		}
		var x0:Int = input[0];
		var x1:Int = input[1];
		var x2:Int = input[2];
		var x3:Int = input[3];
		var x4:Int = input[4];
		var x5:Int = input[5];
		var x6:Int = input[6];
		var x7:Int = input[7];
		var x8:Int = input[8];
		var x9:Int = input[9];
		var x10:Int = input[10];
		var x11:Int = input[11];
		var x12:Int = input[12];
		var x13:Int = input[13];
		var x14:Int = input[14];
		var x15:Int = input[15];

		var h = rounds >> 1;
		for (i in 0...h) {
			x4 ^= rol32(x0 + x12, 7);
			x8 ^= rol32(x4 + x0, 9);
			x12 ^= rol32(x8 + x4, 13);
			x0 ^= rol32(x12 + x8, 18);
			x9 ^= rol32(x5 + x1, 7);
			x13 ^= rol32(x9 + x5, 9);
			x1 ^= rol32(x13 + x9, 13);
			x5 ^= rol32(x1 + x13, 18);
			x14 ^= rol32(x10 + x6, 7);
			x2 ^= rol32(x14 + x10, 9);
			x6 ^= rol32(x2 + x14, 13);
			x10 ^= rol32(x6 + x2, 18);
			x3 ^= rol32(x15 + x11, 7);
			x7 ^= rol32(x3 + x15, 9);
			x11 ^= rol32(x7 + x3, 13);
			x15 ^= rol32(x11 + x7, 18);

			x1 ^= rol32(x0 + x3, 7);
			x2 ^= rol32(x1 + x0, 9);
			x3 ^= rol32(x2 + x1, 13);
			x0 ^= rol32(x3 + x2, 18);
			x6 ^= rol32(x5 + x4, 7);
			x7 ^= rol32(x6 + x5, 9);
			x4 ^= rol32(x7 + x6, 13);
			x5 ^= rol32(x4 + x7, 18);
			x11 ^= rol32(x10 + x9, 7);
			x8 ^= rol32(x11 + x10, 9);
			x9 ^= rol32(x8 + x11, 13);
			x10 ^= rol32(x9 + x8, 18);
			x12 ^= rol32(x15 + x14, 7);
			x13 ^= rol32(x12 + x15, 9);
			x14 ^= rol32(x13 + x12, 13);
			x15 ^= rol32(x14 + x13, 18);
		}
		output[offset] = x0 + input[0];
		output[offset + 1] = x1 + input[1];
		output[offset + 2] = x2 + input[2];
		output[offset + 3] = x3 + input[3];
		output[offset + 4] = x4 + input[4];
		output[offset + 5] = x5 + input[5];
		output[offset + 6] = x6 + input[6];
		output[offset + 7] = x7 + input[7];
		output[offset + 8] = x8 + input[8];
		output[offset + 9] = x9 + input[9];
		output[offset + 10] = x10 + input[10];
		output[offset + 11] = x11 + input[11];
		output[offset + 12] = x12 + input[12];
		output[offset + 13] = x13 + input[13];
		output[offset + 14] = x14 + input[14];
		output[offset + 15] = x15 + input[15];
	}

	private static inline function rol32(x:Int, n:Int):Int32 {
		return ((x << n) | (x >>> (32 - n)));
	}

	private function int32ToBytes(n:Int, bs:Bytes, off:Int):Void {
		bs.set(off, (n));
		bs.set(++off, (n >>> 8));
		bs.set(++off, (n >>> 16));
		bs.set(++off, (n >>> 24));
	}

	private function bytesToInt32(bs:Bytes, off:Int):Int32 {
		var n:Int32 = (bs.get(off));
		n |= (bs.get(++off)) << 8;
		n |= (bs.get(++off)) << 16;
		n |= bs.get(++off) << 24;
		return n;
	}
}
