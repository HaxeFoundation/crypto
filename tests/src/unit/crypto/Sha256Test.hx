package unit.crypto;

import unit.Test;
import haxe.io.Bytes;
import haxe.crypto.Sha256;

class Sha256Test extends Test {
	public function test_hash_sha256():Void {
		eq(Sha256.encode(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		eq(Sha256.encode("The quick brown fox jumps over the lazy dog"), "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
		eq(Sha256.encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
		eq(Sha256.encode("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),"cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
		eq(Sha256.encode("éあ😂"), "d0230b8d8ac2d6d0dbcee11ad0e0eaa68a6565347261871dc241571cab591676");
		eq(Sha256.make(Bytes.ofHex("3636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363600000001")).toHex(),"a83f22d74884bb31c6fb583bef9ffe5e87d126d3585f6d6025d147a8915fc4a8");
	}
}
