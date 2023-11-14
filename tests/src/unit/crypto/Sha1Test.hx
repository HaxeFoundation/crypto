package unit.crypto;

import unit.Test;
import haxe.crypto.Sha1;

class Sha1Test extends Test {
	public function test_hash_sha1():Void {
		eq(Sha1.encode(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
		eq(Sha1.encode("The quick brown fox jumps over the lazy dog"), "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
	}
}
