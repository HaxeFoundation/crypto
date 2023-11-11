package haxe.crypto;

import haxe.io.Bytes;
import haxe.ds.Vector;

class TripleDes extends Des {
	static inline var BLOCK_SIZE:Int = 8;

	private var keys:Vector<Vector<Int64>>;

	public function new(?key:Bytes, ?iv:Bytes) {
		super(key, iv);
		keys = new Vector<Vector<Int64>>(3); // Key size 168 bits
	}

	override public function init(key:Bytes, ?iv:Bytes):Void {
		var keyLength = key.length;
		if (keyLength < 24)
			throw "Specified key is not a valid size for 3Des algorithm";

		this.iv = iv;
		keys[0] = keygen(key);
		keys[1] = keygen(key, 8);
		keys[2] = keygen(key, 16);
	}

	private function enc(block:Int64, mode:Bool, idx:Int):Int64 {
		return cipher(block, mode, keys[idx]);
	}

	override private function encryptBlock(src:Bytes, srcIndex:Int, dst:Bytes, dstIndex:Int):Void {
		var block = bytesToInt64(src, srcIndex);
		var xb = enc(enc(enc(block, true, 0), false, 1), true, 2);
		int64ToBytes(xb, dst, dstIndex);
	}

	override private function decryptBlock(src:Bytes, srcIndex:Int, dst:Bytes, dstIndex:Int):Void {
		var block = bytesToInt64(src, srcIndex);
		var xb = enc(enc(enc(block, false, 2), true, 1), false, 0);
		int64ToBytes(xb, dst, dstIndex);
	}
}
