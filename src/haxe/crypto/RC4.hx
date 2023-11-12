package haxe.crypto;

import haxe.io.Bytes;
import haxe.ds.Vector;

class RC4 {
	static var sBox:Vector<Int>;

	public function new(?key:Bytes) {
		sBox = new Vector<Int>(256);
		if (key != null)
			init(key);
	}

	public function init(key:Bytes):Void {
		var klen:Int = key.length;
		var j:Int = 0, k:Int = 0;
		for (i in 0...256)
			sBox[i] = i;
		for (i in 0...256) {
			j = (j + sBox[i] + key.get(i % klen)) & 255;
			k = sBox[i];
			sBox[i] = sBox[j];
			sBox[j] = k;
		}
	}

	public function encrypt(data:Bytes):Bytes {
		var out:Bytes = Bytes.alloc(data.length);
		var l:Int = 0, j:Int = 0, k:Int = 0;
		for (i in 0...data.length) {
			l = (l + 1) & 255;
			j = (j + sBox[l]) & 255;
			k = sBox[l];
			sBox[l] = sBox[j];
			sBox[j] = k;
			out.set(i, data.get(i) ^ sBox[(sBox[l] + sBox[j]) & 255]);
		}
		return out;
	}

	public function decrypt(data:Bytes):Bytes {
		return encrypt(data);
	}
}
