package haxe.crypto;

import haxe.crypto.Hmac.HashMethod;
import haxe.io.Bytes;

class Pbkdf2 {
	var hmac:Hmac;

	public function new(?hashMethod:HashMethod) {
		hmac = new Hmac(hashMethod);
	}

	public function init(hashMethod:HashMethod):Void {
		hmac.init(hashMethod);
	}

	public function encode(password:Bytes, salt:Bytes, iterations:Int = 4096, keyLen:Int = 20):Bytes {
		var hLen = hmac.getSize();
		var len = Math.ceil(keyLen / hLen);
		var r = keyLen - (len - 1) * hLen;
		var destPos = 0;
		var result = Bytes.alloc(len * hLen);
		var sl = salt.length;
		var i = 1;
		while (i <= len) {
			var block = Bytes.alloc(hLen);
			var u = Bytes.alloc(sl + 4);
			u.blit(0, salt, 0, sl);

			u.set(sl, i >>> 24);
			u.set(sl + 1, i >>> 16);
			u.set(sl + 2, i >>> 8);
			u.set(sl + 3, i);

			for (j in 0...iterations) {
				u = hmac.make(password, u);
				for (k in 0...block.length) {
					block.set(k, block.get(k) ^ u.get(k));
				}
			}
			result.blit(destPos, block, 0, hLen);
			destPos += hLen;
			i++;
		}
		if (r < hLen) {
			var deriveKey = Bytes.alloc(keyLen);
			deriveKey.blit(0, result, 0, keyLen);
			return deriveKey;
		}

		return result;
	}
}
