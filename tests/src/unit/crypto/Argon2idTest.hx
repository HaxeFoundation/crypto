package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.io.Bytes;
import haxe.crypto.Argon2id;

class Argon2idTest extends Test {
	public function test():Void {
		trace("Argon2id Test");
		var time = Timer.stamp();
		
		var password = Bytes.alloc(32);
		for (i in 0...32) password.set(i, 0x01);
		
		var salt = Bytes.alloc(16);
		for (i in 0...16) salt.set(i, 0x02);
		
		var secret = Bytes.alloc(8);
		for (i in 0...8) secret.set(i, 0x03);
		
		var ad = Bytes.alloc(12);
		for (i in 0...12) ad.set(i, 0x04);
		
		var expected = "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659";
		
		var hash = Argon2id.hash(password, salt, 3, 32, 4, 32, secret, ad);
		eq(hash.toHex().toLowerCase(), expected);
		
		time = Timer.stamp() - time;
		trace("Finished : " + time + " seconds");
	}
}
