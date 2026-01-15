package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.io.Bytes;
import haxe.crypto.Argon2i;

class Argon2iTest extends Test {
	public function test():Void {
		trace("Argon2i Test");
		var time = Timer.stamp();
		
		var password = Bytes.alloc(32);
		for (i in 0...32) password.set(i, 0x01);
		
		var salt = Bytes.alloc(16);
		for (i in 0...16) salt.set(i, 0x02);
		
		var secret = Bytes.alloc(8);
		for (i in 0...8) secret.set(i, 0x03);
		
		var ad = Bytes.alloc(12);
		for (i in 0...12) ad.set(i, 0x04);
		
		var expected = "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8";
		
		var hash = Argon2i.hash(password, salt, 3, 32, 4, 32, secret, ad);
		eq(hash.toHex().toLowerCase(), expected);
		
		time = Timer.stamp() - time;
		trace("Finished : " + time + " seconds");
	}
}
