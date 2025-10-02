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
	
	public function test_hash_sha256_update_digest():Void {
		var sha = new Sha256();
		var result = sha.digest();
		eq(result.toHex(), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

		sha = new Sha256();
		sha.update(Bytes.ofString("The quick brown fox jumps over the lazy dog"));
		result = sha.digest();
		eq(result.toHex(), "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");

		sha = new Sha256();
		sha.update(Bytes.ofString("The quick brown "));
		sha.update(Bytes.ofString("fox jumps over "));
		sha.update(Bytes.ofString("the lazy dog"));
		result = sha.digest();
		eq(result.toHex(), "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");

		sha = new Sha256();
		sha.update(Bytes.ofString("abcdbcdecdefdefgefghfghighij"));
		sha.update(Bytes.ofString("hijkijkljklmklmnlmnomnopnopq"));
		result = sha.digest();
		eq(result.toHex(), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

		sha = new Sha256();
		sha.update(Bytes.ofString("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"));
		sha.update(Bytes.ofString("ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
		result = sha.digest();
		eq(result.toHex(), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");

		sha = new Sha256();
		sha.update(Bytes.ofString("é"));
		sha.update(Bytes.ofString("あ"));
		sha.update(Bytes.ofString("😂"));
		result = sha.digest();
		eq(result.toHex(), "d0230b8d8ac2d6d0dbcee11ad0e0eaa68a6565347261871dc241571cab591676");

		sha = new Sha256();
		sha.update(Bytes.ofHex("3636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363600000001"));
		result = sha.digest();
		eq(result.toHex(), "a83f22d74884bb31c6fb583bef9ffe5e87d126d3585f6d6025d147a8915fc4a8");

		sha = new Sha256();
		var testStr = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
		var bytes = Bytes.ofString(testStr);
		for (i in 0...bytes.length) {
			sha.update(Bytes.ofData(bytes.sub(i, 1).getData()));
		}
		result = sha.digest();
		eq(result.toHex(), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
	}

	public function test_hash_sha256_consistency():Void {
		var testStrings = [
			"",
			"a",
			"abc",
			"message digest",
			"abcdefghijklmnopqrstuvwxyz",
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			"The quick brown fox jumps over the lazy dog"
		];

		for (str in testStrings) {
			var expected = Sha256.encode(str);
			var sha = new Sha256();
			sha.update(Bytes.ofString(str));
			var result = sha.digest();
			eq(result.toHex(), expected);
		}

		var bytes = Bytes.ofString("test data for consistency check");
		var expectedBytes = Sha256.make(bytes);
		var sha = new Sha256();
		sha.update(bytes);
		var resultBytes = sha.digest();
		eq(resultBytes.toHex(), expectedBytes.toHex());

		var longStr = "This is a longer test string that will be split into multiple chunks to verify consistency";
		var expected = Sha256.encode(longStr);
		sha = new Sha256();
		var longBytes = Bytes.ofString(longStr);
		var chunkSize = 10;
		var pos = 0;
		while (pos < longBytes.length) {
			var len = chunkSize;
			if (pos + len > longBytes.length) len = longBytes.length - pos;
			sha.update(longBytes.sub(pos, len));
			pos += chunkSize;
		}
		var result = sha.digest();
		eq(result.toHex(), expected);
	}
}
