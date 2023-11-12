package haxe.crypto;

import haxe.ds.Vector;
import haxe.io.Bytes;

class XChaCha20 extends ChaCha {
	override public function init(key:Bytes, nonce:Bytes, ?counter:Int64):Void {
		if (nonce == null || nonce.length < 16)
			throw "Nonce must be at least 16 bytes";
		if (key == null || key.length != 32)
			throw "Key must be 32 bytes";

		nonceLength = nonce.length;

		setConstant(key);

		var subKey = getSubKey(key, nonce);
		for (i in 0...subKey.length)
			state[i + 4] = subKey[i];

		state[14] = bytesToInt32(nonce, 16);
		state[15] = bytesToInt32(nonce, 20);

		reset();
		if (counter != null)
			setCounter(counter);
	}

	private function getSubKey(key:Bytes, nonce:Bytes):Vector<Int> {
		super.setKey(key);
		for (i in 0...4)
			state[i + 12] = bytesToInt32(nonce, i * 4);
		var chachaBuffer:Vector<Int> = new Vector<Int>(16);
		generateBlock(state, chachaBuffer, 20);
		var subKey:Vector<Int> = new Vector<Int>(8);
		for (i in 0...4)
			subKey[i] = chachaBuffer[i] - state[i];
		for (i in 12...16)
			subKey[i - 8] = chachaBuffer[i] - state[i];
		return subKey;
	}

	override public function resetCounter():Void {
		counter = 0;
		state[12] = state[13] = 0;
	}

	override public function setNonce(nonce:Bytes):Void {
		throw "Use init(key,nonce) method for initialization";
	}

	override public function setKey(key:Bytes):Void {
		throw "Use init(key,nonce) method for initialization";
	}
}
