package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.io.Bytes;
import haxe.crypto.random.SecureRandom;

class SecureRandomTest extends Test {
	public function test_securerandom():Void {
		trace("SecureRandom tests");
		var time = Timer.stamp();
		var randomInt = SecureRandom.int();
		if ( randomInt < -2147483648 || randomInt > 2147483647) {
			throw "Secure random Int test failed";
		}
		var randomBytes = SecureRandom.bytes(16);
		if (randomBytes == null || randomBytes.length != 16) {
			throw "Secure random Bytes test failed";
		}
		var randomFloat = SecureRandom.float();
		if (randomFloat < 0.0 || randomFloat >= 1.0) {
			throw "Secure random Float test failed";
		}
		time = Timer.stamp() - time;
		trace("Finished SecureRandom: " + time + " seconds");
	}
}
