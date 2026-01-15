package haxe.crypto;

import haxe.io.Bytes;
import haxe.ds.Vector;
import haxe.Int64;

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
	static inline var KEYED_HASH = 1 << 4;
	static inline var DERIVE_KEY_CONTEXT = 1 << 5;
	static inline var DERIVE_KEY_MATERIAL = 1 << 6;

	var key:Vector<Int>;
	var cvStack:Array<Vector<Int>>;
	var cvStackLen:Int;
	var outlen:Int;
	var flags:Int;

	var chunkCV:Vector<Int>;
	var chunkBlock:Vector<Int>;
	var chunkBlockLen:Int;
	var chunkBlocksCompressed:Int;
	var chunkCounter:Int64;
	
	public function new(outlen:Int = 32, keyBytes:Bytes = null, context:String = null) {
		this.outlen = outlen;
		this.flags = 0;

		if (keyBytes != null && keyBytes.length == 32) {
			// Keyed hash mode
			this.key = new Vector<Int>(8);
			for (i in 0...8) {
				var off = i << 2;
				this.key[i] = keyBytes.get(off) | (keyBytes.get(off + 1) << 8) | 
					(keyBytes.get(off + 2) << 16) | (keyBytes.get(off + 3) << 24);
			}
			this.flags = KEYED_HASH;
		} else if (context != null) {
			// Key derivation mode
			var contextBytes = Bytes.ofString(context);
			var contextHasher = new Blake3(32, null, null);
			contextHasher.flags = DERIVE_KEY_CONTEXT;
			contextHasher.update(contextBytes);
			var contextKey = contextHasher.digest();
			
			this.key = new Vector<Int>(8);
			for (i in 0...8) {
				var off = i << 2;
				this.key[i] = contextKey.get(off) | (contextKey.get(off + 1) << 8) | 
					(contextKey.get(off + 2) << 16) | (contextKey.get(off + 3) << 24);
			}
			this.flags = DERIVE_KEY_MATERIAL;
		} else {
			// Regular hash mode
			this.key = IV;
		}

		cvStack = [];
		cvStackLen = 0;
		chunkCounter = Int64.make(0, 0);
		initChunk();
	}

	inline function initChunk() {
		chunkCV = new Vector<Int>(8);
		for (i in 0...8)
			chunkCV[i] = key[i];
		chunkBlock = new Vector<Int>(16);
		for (i in 0...16)
			chunkBlock[i] = 0;
		chunkBlockLen = 0;
		chunkBlocksCompressed = 0;
	}

	inline function chunkComplete():Bool {
		return chunkBlocksCompressed == 16 || (chunkBlocksCompressed == 15 && chunkBlockLen == 64);
	}

	function updateChunk(data:Bytes):Int {
		var len = data.length;
		var pos = 0;

		while (len > 0 && !chunkComplete()) {
			if (chunkBlockLen == 64) {
				var blockFlags = flags;
				if (chunkBlocksCompressed == 0)
					blockFlags |= CHUNK_START;
				var full = compress(chunkCV, chunkBlock, 64, chunkCounter, blockFlags);
				for (i in 0...8)
					chunkCV[i] = full[i];
				chunkBlocksCompressed++;
				// Clear the block
				for (i in 0...16)
					chunkBlock[i] = 0;
				chunkBlockLen = 0;
			}

			var want = 64 - chunkBlockLen;
			var take = len < want ? len : want;

			// Pack bytes (little-endian)
			for (i in 0...take) {
				var bytePos = chunkBlockLen + i;
				var wordIdx = bytePos >> 2;
				var byteInWord = bytePos & 3;  // mod 4
				var byte = data.get(pos + i);
				chunkBlock[wordIdx] |= (byte << (byteInWord * 8));
			}

			chunkBlockLen += take;
			pos += take;
			len -= take;
		}

		return pos;
	}

	function outputChunkCV():Vector<Int> {
		var blockFlags = flags | CHUNK_END;
		if (chunkBlocksCompressed == 0)
			blockFlags |= CHUNK_START;
		
		var full = compress(chunkCV, chunkBlock, chunkBlockLen, chunkCounter, blockFlags);
		var result = new Vector<Int>(8);
		for (i in 0...8)
			result[i] = full[i];
		return result;
	}

	function addChunkCV(cv:Vector<Int>, totalChunks:Int64) {
		while ((totalChunks.low & 1) == 0 && cvStackLen > 0) {
			cvStackLen--;
			cv = parentCV(cvStack[cvStackLen], cv);
			totalChunks = Int64.shr(totalChunks, 1);
		}
		
		if (cvStackLen >= cvStack.length) {
			cvStack.push(cv);
		} else {
			cvStack[cvStackLen] = cv;
		}
		cvStackLen++;
	}

	function parentCV(leftCV:Vector<Int>, rightCV:Vector<Int>):Vector<Int> {
		var block = new Vector<Int>(16);
		for (i in 0...8)
			block[i] = leftCV[i];
		for (i in 0...8)
			block[i + 8] = rightCV[i];
		
		var full = compress(key, block, 64, Int64.make(0, 0), PARENT | flags);
		var result = new Vector<Int>(8);
		for (i in 0...8)
			result[i] = full[i];
		return result;
	}
	
	function parentOutput(leftCV:Vector<Int>, rightCV:Vector<Int>):Vector<Int> {
		var block = new Vector<Int>(16);
		for (i in 0...8)
			block[i] = leftCV[i];
		for (i in 0...8)
			block[i + 8] = rightCV[i];
		return block;
	}

	public function update(data:Bytes) {
		var pos = 0;
		var len = data.length;

		while (len > 0) {
			if (chunkComplete()) {
				var cv = outputChunkCV();
				var totalChunks = Int64.add(chunkCounter, Int64.make(0, 1));
				addChunkCV(cv, totalChunks);
				chunkCounter = totalChunks;
				initChunk();
			}

			var n = updateChunk(data.sub(pos, len));
			pos += n;
			len -= n;
		}
	}

	public function digest():Bytes {
		var out = Bytes.alloc(outlen);
		var outPos = 0;

		var node:Vector<Int>;
		var nodeCV:Vector<Int>;
		var nodeLen:Int;
		var nodeCounter:Int64;
		var nodeFlags:Int;
		
		if (cvStackLen == 0) {
			// Single chunk
			nodeFlags = flags | CHUNK_END | ROOT;
			if (chunkBlocksCompressed == 0)
				nodeFlags |= CHUNK_START;
			node = chunkBlock;
			nodeCV = chunkCV;
			nodeLen = chunkBlockLen;
			nodeCounter = Int64.make(0, 0);
		} else {
			// Multiple chunks
			var cv = outputChunkCV();
			var blockWords:Vector<Int> = null;
			var i = cvStackLen;
			while (i > 0) {
				i--;
				var leftCV = cvStack[i];
				blockWords = parentOutput(leftCV, cv);
				var full = compress(key, blockWords, 64, Int64.make(0, 0), PARENT | flags);
				cv = new Vector<Int>(8);
				for (k in 0...8)
					cv[k] = full[k];
			}
			
			node = blockWords;
			nodeCV = key;
			nodeLen = 64;
			nodeCounter = Int64.make(0, 0);
			nodeFlags = ROOT | PARENT | flags;
		}
		
		var outputBlockCounter = 0;
		while (outPos < outlen) {
			var words = compress(nodeCV, node, nodeLen, Int64.make(0, outputBlockCounter), nodeFlags);
			for (i in 0...16) {
				if (outPos >= outlen) break;
				var word = words[i];
				for (j in 0...4) {
					if (outPos >= outlen) break;
					out.set(outPos++, (word >> (j << 3)) & 0xff);
				}
			}
			outputBlockCounter++;
		}

		return out;
	}

	static function compress(cv:Vector<Int>, block:Vector<Int>, blockLen:Int, counter:Int64, flags:Int):Vector<Int> {
		var state = new Vector<Int>(16);
		for (i in 0...8)
			state[i] = cv[i];
		state[8] = IV[0];
		state[9] = IV[1];
		state[10] = IV[2];
		state[11] = IV[3];
		state[12] = counter.low;
		state[13] = counter.high;
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

		var result = new Vector<Int>(16);
		for (i in 0...8) {
			result[i] = state[i] ^ state[i + 8];
			result[i + 8] = state[i + 8] ^ cv[i];
		}
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

	public static function keyedHash(key:Bytes, data:Bytes, outlen:Int = 32):Bytes {
		var ctx = new Blake3(outlen, key);
		ctx.update(data);
		return ctx.digest();
	}

	public static function deriveKey(context:String, material:Bytes, outlen:Int = 32):Bytes {
		var ctx = new Blake3(outlen, null, context);
		ctx.update(material);
		return ctx.digest();
	}
}