package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.io.Bytes;
import haxe.crypto.Sha384;

class Sha384Test extends Test {
	public function test():Void {
		trace("Sha384 started...");
		var time = Timer.stamp();

		eq(Sha384.encode(""), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
		eq(Sha384.encode("abc"), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
		eq(Sha384.encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
			"3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
		eq(Sha384.encode("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
			"09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
		eq(Sha384.encode("éあ😂"), "d1d1ece7af1b07ac3c82fe0215dd3b15f7145ae1ccaf30976e49e5c012e5286e0f9bcd5e9c04142c9c98485087ce4d9f");

		time = Timer.stamp() - time;
		trace("Finished : " + time + " seconds");
	}
	
	public function test_hash_sha384_update_digest():Void {
		trace("Sha384 update/digest tests started...");
		var time = Timer.stamp();

		var sha = new Sha384();
		var result = sha.digest();
		eq(result.toHex(), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");

		sha = new Sha384();
		sha.update(Bytes.ofString("abc"));
		result = sha.digest();
		eq(result.toHex(), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");

		sha = new Sha384();
		sha.update(Bytes.ofString("abcdbcdecdefdefgefghfghighij"));
		sha.update(Bytes.ofString("hijkijkljklmklmnlmnomnopnopq"));
		result = sha.digest();
		eq(result.toHex(), "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");

		sha = new Sha384();
		sha.update(Bytes.ofString("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"));
		sha.update(Bytes.ofString("ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"));
		result = sha.digest();
		eq(result.toHex(), "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");

		sha = new Sha384();
		sha.update(Bytes.ofString("é"));
		sha.update(Bytes.ofString("あ"));
		sha.update(Bytes.ofString("😂"));
		result = sha.digest();
		eq(result.toHex(), "d1d1ece7af1b07ac3c82fe0215dd3b15f7145ae1ccaf30976e49e5c012e5286e0f9bcd5e9c04142c9c98485087ce4d9f");

		sha = new Sha384();
		var testStr = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
		var bytes = Bytes.ofString(testStr);
		for (i in 0...bytes.length) {
			sha.update(Bytes.ofData(bytes.sub(i, 1).getData()));
		}
		result = sha.digest();
		eq(result.toHex(), "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");

		time = Timer.stamp() - time;
		trace("Update/digest tests finished : " + time + " seconds");
	}

	public function test_hash_sha384_consistency():Void {
		var testStrings = [
			"",
			"a",
			"abc",
			"message digest",
			"abcdefghijklmnopqrstuvwxyz",
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
		];

		for (str in testStrings) {
			var expected = Sha384.encode(str);
			var sha = new Sha384();
			sha.update(Bytes.ofString(str));
			var result = sha.digest();
			eq(result.toHex(), expected);
		}

		var bytes = Bytes.ofString("test data for SHA-384 consistency check");
		var expectedBytes = Sha384.make(bytes);
		var sha = new Sha384();
		sha.update(bytes);
		var resultBytes = sha.digest();
		eq(resultBytes.toHex(), expectedBytes.toHex());

		var longStr = "This is a longer test string for SHA-384 that will be split into multiple chunks to verify consistency across block boundaries which are 128 bytes for SHA-384";
		var expected = Sha384.encode(longStr);
		sha = new Sha384();
		var longBytes = Bytes.ofString(longStr);
		var chunkSize = 20;
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
