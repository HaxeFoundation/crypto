package unit.crypto;

import unit.Test;
import haxe.crypto.Crc32;
import haxe.io.Bytes;

class Crc32Test extends Test {
	public function test_hash_crc32():Void {
		eq(Crc32.make(Bytes.ofString("")),0);
		eq(Crc32.make(Bytes.ofString("The quick brown fox jumps over the lazy dog")), 0x414FA339);
		eq(Crc32.make(Bytes.ofString("a")),0xe8b7be43);
		eq(Crc32.make(Bytes.ofString("abc")),0x352441c2);
		eq(Crc32.make(Bytes.ofString("message digest")),0x20159d7f);
		eq(Crc32.make(Bytes.ofString("abcdefghijklmnopqrstuvwxyz")),0x4c2750bd);
		eq(Crc32.make(Bytes.ofString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),0x1fc2e6d2);
		eq(Crc32.make(Bytes.ofString("12345678901234567890123456789012345678901234567890123456789012345678901234567890")),0x7ca94a72);
	}
}
