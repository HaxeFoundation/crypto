package unit.crypto;

import unit.Test;
import haxe.io.Bytes;
import haxe.crypto.Sha224;

class Sha224Test extends Test {
	public function test_hash_sha224():Void {
		eq(Sha224.encode(""), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
		eq(Sha224.encode("abc"), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
		eq(Sha224.encode("The quick brown fox jumps over the lazy dog"), "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525");
		eq(Sha224.encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
		eq(Sha224.encode("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
			"c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3");
		eq(Sha224.encode("éあ😂"), "d7967c5f27bd6868e276647583c55ab09d5f45b40610a3d9c6d91b90");
	}
	
	public function test_hash_sha224_update_digest():Void {
		var sha = new Sha224();
		var result = sha.digest();
		eq(result.toHex(), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");

		sha = new Sha224();
		sha.update(Bytes.ofString("abc"));
		result = sha.digest();
		eq(result.toHex(), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");

		sha = new Sha224();
		sha.update(Bytes.ofString("The quick brown fox "));
		sha.update(Bytes.ofString("jumps over "));
		sha.update(Bytes.ofString("the lazy dog"));
		result = sha.digest();
		eq(result.toHex(), "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525");

		sha = new Sha224();
		sha.update(Bytes.ofString("abcdbcdecdefdefgefghfghighijhijkijkljklmklm"));
		sha.update(Bytes.ofString("nlmnomnopnopq"));
		result = sha.digest();
		eq(result.toHex(), "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");

		sha = new Sha224();
		sha.update(Bytes.ofString("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"));
		sha.update(Bytes.ofString("ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
		result = sha.digest();
		eq(result.toHex(), "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3");

		sha = new Sha224();
		sha.update(Bytes.ofString("éあ"));
		sha.update(Bytes.ofString("😂"));
		result = sha.digest();
		eq(result.toHex(), "d7967c5f27bd6868e276647583c55ab09d5f45b40610a3d9c6d91b90");

		sha = new Sha224();
		var testStr = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
		var bytes = Bytes.ofString(testStr);
		for (i in 0...bytes.length) {
			sha.update(Bytes.ofData(bytes.sub(i, 1).getData()));
		}
		result = sha.digest();
		eq(result.toHex(), "c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3");
	}

	public function test_hash_sha224_consistency():Void {
		var testStrings = [
			"",
			"a",
			"abc",
			"message digest",
			"abcdefghijklmnopqrstuvwxyz",
			"The quick brown fox jumps over the lazy dog"
		];

		for (str in testStrings) {
			var expected = Sha224.encode(str);
			var sha = new Sha224();
			sha.update(Bytes.ofString(str));
			var result = sha.digest();
			eq(result.toHex(), expected);
		}

		var bytes = Bytes.ofString("test data");
		var expectedBytes = Sha224.make(bytes);
		var sha = new Sha224();
		sha.update(bytes);
		var resultBytes = sha.digest();
		eq(resultBytes.toHex(), expectedBytes.toHex());
	}
}
