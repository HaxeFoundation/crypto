package haxe.crypto.mode;

import haxe.io.Bytes;

class CTR {
	public static function encrypt(src:Bytes, iv:Bytes, blockSize:Int, encryptBlock:Bytes->Int->Bytes->Int->Void):Void {
		var vkey:Bytes = iv.sub(0, iv.length);
		var i:Int = 0;
		var len:Int = src.length;
		while (i < len)
		{
			var vector:Bytes = vkey.sub(0, vkey.length);
			encryptBlock(vector, 0, vector, 0);
			var block:Int = (i + blockSize) > len ? len - i : blockSize;
			for (j in 0...block)
			{
				src.set(i + j, src.get(i + j) ^ vector.get(j));
			}
			var carry:Int = 1;
			var j = vkey.length - 1;
			while (j >= 0 && carry > 0) {
				var newVal = vkey.get(j) + carry;
				vkey.set(j, newVal & 0xFF);
				carry = newVal >> 8;
				j--;
			}
			i += blockSize;
		}
	}

	public static function decrypt(src:Bytes, iv:Bytes, blockSize:Int, decryptBlock:Bytes->Int->Bytes->Int->Void):Void {
		encrypt(src, iv, blockSize, decryptBlock);
	}
}
