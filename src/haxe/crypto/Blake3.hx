package haxe.crypto;

import haxe.io.Bytes;
import haxe.ds.Vector;

class Blake3 {
	static inline var CHUNK_SIZE = 1024;
	static inline var BLOCK_SIZE = 64;

	static var IV:Vector<Int> = Vector.fromArrayCopy([
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	]);

	static var MSG_SCHEDULE:Vector<Vector<Int>> = Vector.fromArrayCopy([
		Vector.fromArrayCopy([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
		Vector.fromArrayCopy([2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]),
		Vector.fromArrayCopy([3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1]),
		Vector.fromArrayCopy([10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6]),
		Vector.fromArrayCopy([12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4]),
		Vector.fromArrayCopy([9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7]),
		Vector.fromArrayCopy([11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13])
	]);

	static inline var CHUNK_START = 1 << 0;
	static inline var CHUNK_END = 1 << 1;
	static inline var PARENT = 1 << 2;
	static inline var ROOT = 1 << 3;

	var key:Vector<Int>;
	var cvStack:Array<Vector<Int>>;
	var outlen:Int;

	var chunkCV:Vector<Int>;
	var chunkBlock:Vector<Int>;
	var chunkBlockLen:Int;
	var chunkBlocksCompressed:Int;
	var chunkCounter:Int;
	var chunkFlags:Int;

	public function new(outlen:Int = 32, keyBytes:Bytes = null) {
		this.outlen = outlen;

		if (keyBytes != null && keyBytes.length == 32) {
			this.key = new Vector<Int>(8);
			for (i in 0...8) {
				var off = i << 2;
				this.key[i] = keyBytes.get(off) | (keyBytes.get(off + 1) << 8) | (keyBytes.get(off + 2) << 16) | (keyBytes.get(off + 3) << 24);
			}
		} else {
			this.key = IV;
		}

		cvStack = [];
		initChunk(0, 0);
	}

	inline function initChunk(counter:Int, flags:Int) {
		chunkCV = new Vector<Int>(8);
		for (i in 0...8)
			chunkCV[i] = key[i];
		chunkBlock = new Vector<Int>(16);
		for (i in 0...16)
			chunkBlock[i] = 0;
		chunkBlockLen = 0;
		chunkBlocksCompressed = 0;
		chunkCounter = counter;
		chunkFlags = flags;
	}

	inline function chunkComplete():Bool {
		return chunkBlocksCompressed == 16;
	}

	function updateChunk(data:Bytes):Int {
		var len = data.length;
		var pos = 0;

		while (len > 0 && !chunkComplete()) {
			if (chunkBlockLen == 64) {
				var blockFlags = chunkFlags;
				if (chunkBlocksCompressed == 0)
					blockFlags |= CHUNK_START;
				chunkCV = compress(chunkCV, chunkBlock, 64, chunkCounter, blockFlags);
				chunkBlocksCompressed++;
				for (i in 0...16)
					chunkBlock[i] = 0;
				chunkBlockLen = 0;
			}

			var take = 64 - chunkBlockLen;
			if (take > len)
				take = len;

			for (i in 0...take) {
				var wordIdx = (chunkBlockLen + i) >> 2;
				var byteIdx = (chunkBlockLen + i) & 3;
				var byte = data.get(pos + i);
				chunkBlock[wordIdx] = chunkBlock[wordIdx] | (byte << (byteIdx << 3));
			}

			chunkBlockLen += take;
			pos += take;
			len -= take;
		}

		return pos;
	}

	function outputChunkCV():Vector<Int> {
		var blockFlags = chunkFlags | CHUNK_END;
		if (chunkBlocksCompressed == 0)
			blockFlags |= CHUNK_START;
		return compress(chunkCV, chunkBlock, chunkBlockLen, chunkCounter, blockFlags);
	}

	function addChunkCV(cv:Vector<Int>, totalChunks:Int) {
		while (totalChunks > 0 && (totalChunks & 1) == 0) {
			cv = parentOutput(cvStack.pop(), cv);
			totalChunks >>= 1;
		}
		cvStack.push(cv);
	}

	function parentOutput(left:Vector<Int>, right:Vector<Int>):Vector<Int> {
		var block = new Vector<Int>(16);
		for (i in 0...8)
			block[i] = left[i];
		for (i in 0...8)
			block[i + 8] = right[i];
		return compress(key, block, 64, 0, PARENT);
	}

	public function update(data:Bytes) {
		var pos = 0;
		var len = data.length;

		while (len > 0) {
			if (chunkComplete()) {
				var cv = outputChunkCV();
				addChunkCV(cv, chunkCounter);
				initChunk(chunkCounter + 1, 0);
			}

			var n = updateChunk(data.sub(pos, len));
			pos += n;
			len -= n;
		}
	}

	public function digest():Bytes {
		var out = Bytes.alloc(outlen);
		var outPos = 0;

		if (cvStack.length == 0) {
			var blockFlags = chunkFlags | CHUNK_END | ROOT;
			if (chunkBlocksCompressed == 0)
				blockFlags |= CHUNK_START;

			var outputBlockCounter = 0;
			while (outPos < outlen) {
				var words = compress(chunkCV, chunkBlock, chunkBlockLen, outputBlockCounter, blockFlags);

				for (i in 0...8) {
					if (outPos >= outlen)
						break;
					var word = words[i];
					for (j in 0...4) {
						if (outPos >= outlen)
							break;
						out.set(outPos++, (word >> (j << 3)) & 0xff);
					}
				}
				outputBlockCounter++;
			}
		} else {
			var cv = outputChunkCV();
			while (cvStack.length > 0)
				cv = parentOutput(cvStack.pop(), cv);

			var block = new Vector<Int>(16);
			for (i in 0...8)
				block[i] = cv[i];

			var outputBlockCounter = 0;
			while (outPos < outlen) {
				var words = compress(key, block, 64, outputBlockCounter, ROOT | PARENT);

				for (i in 0...8) {
					if (outPos >= outlen)
						break;
					var word = words[i];
					for (j in 0...4) {
						if (outPos >= outlen)
							break;
						out.set(outPos++, (word >> (j << 3)) & 0xff);
					}
				}
				outputBlockCounter++;
			}
		}

		return out;
	}

	static function compress(cv:Vector<Int>, block:Vector<Int>, blockLen:Int, counter:Int, flags:Int):Vector<Int> {
		var state = new Vector<Int>(16);
		for (i in 0...8)
			state[i] = cv[i];
		state[8] = IV[0];
		state[9] = IV[1];
		state[10] = IV[2];
		state[11] = IV[3];
		state[12] = counter;
		state[13] = 0;
		state[14] = blockLen;
		state[15] = flags;

		for (round in 0...7) {
			var s = MSG_SCHEDULE[round];

			g(state, 0, 4, 8, 12, block[s[0]], block[s[1]]);
			g(state, 1, 5, 9, 13, block[s[2]], block[s[3]]);
			g(state, 2, 6, 10, 14, block[s[4]], block[s[5]]);
			g(state, 3, 7, 11, 15, block[s[6]], block[s[7]]);

			g(state, 0, 5, 10, 15, block[s[8]], block[s[9]]);
			g(state, 1, 6, 11, 12, block[s[10]], block[s[11]]);
			g(state, 2, 7, 8, 13, block[s[12]], block[s[13]]);
			g(state, 3, 4, 9, 14, block[s[14]], block[s[15]]);
		}

		var result = new Vector<Int>(8);
		for (i in 0...8)
			result[i] = state[i] ^ state[i + 8];
		return result;
	}

	static inline function g(state:Vector<Int>, a:Int, b:Int, c:Int, d:Int, mx:Int, my:Int) {
		state[a] = (state[a] + state[b] + mx) | 0;
		state[d] = rotr32(state[d] ^ state[a], 16);
		state[c] = (state[c] + state[d]) | 0;
		state[b] = rotr32(state[b] ^ state[c], 12);
		state[a] = (state[a] + state[b] + my) | 0;
		state[d] = rotr32(state[d] ^ state[a], 8);
		state[c] = (state[c] + state[d]) | 0;
		state[b] = rotr32(state[b] ^ state[c], 7);
	}

	static inline function rotr32(x:Int, n:Int):Int {
		return (x >>> n) | (x << (32 - n));
	}

	public static function hash(data:Bytes, outlen:Int = 32):Bytes {
		var ctx = new Blake3(outlen);
		ctx.update(data);
		return ctx.digest();
	}
}