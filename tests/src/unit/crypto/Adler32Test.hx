package unit.crypto;

import unit.Test;
import haxe.crypto.Adler32;
import haxe.io.Bytes;

class Adler32Test extends Test {
	public function test_hash_Adler32():Void {
		eq(Adler32.make(Bytes.ofString("")),0x00000001);
		eq(Adler32.make(Bytes.ofString("a")), 0x00620062);
		eq(Adler32.make(Bytes.ofString("abc")), 0x024d0127);
		eq(Adler32.make(Bytes.ofString("message digest")), 0x29750586);
		eq(Adler32.make(Bytes.ofString("abcdefghijklmnopqrstuvwxyz")), 0x90860b20);
		eq(Adler32.make(Bytes.ofString("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")), 0x8adb150c);
		eq(Adler32.make(Bytes.ofString("12345678901234567890123456789012345678901234567890123456789012345678901234567890")), 0x97b61069);
	}
}
