package unit.crypto;

import unit.Test;
import haxe.crypto.Md5;

class Md5Test extends Test {
	public function test_hash_md5():Void {
		eq(Md5.encode(""), "d41d8cd98f00b204e9800998ecf8427e");
		eq(Md5.encode("The quick brown fox jumps over the lazy dog"), "9e107d9d372bb6826bd81d3542a419d6");
		eq(Md5.encode("a"), "0cc175b9c0f1b6a831c399e269772661");
		eq(Md5.encode("abc"), "900150983cd24fb0d6963f7d28e17f72");
		eq(Md5.encode("message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
		eq(Md5.encode("abcdefghijklmnopqrstuvwxyz"), "c3fcd3d76192e4007dfb496cca67e13b");
		eq(Md5.encode("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), "d174ab98d277d9f5a5611c2c9f419d9f");
		eq(Md5.encode("12345678901234567890123456789012345678901234567890123456789012345678901234567890"), "57edf4a22be3c955ac49da2e2107b67a");
	}
}
