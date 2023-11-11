package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.crypto.Sha512;

class Sha512Test extends Test {
	public function test():Void {
		trace("Sha512 started...");
		var time = Timer.stamp();

		eq(Sha512.encode(""),
			"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
		eq(Sha512.encode("abc"),
			"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
		eq(Sha512.encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
			"204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
		eq(Sha512.encode("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
			"8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
		eq(Sha512.encode("éあ😂"),
			"239799aae390b741ebc847c3eb0f171c3d51664dfd6001cf20d32884d9e2e6733bd23f70b3740ada04eaaa1ffe6515792bf491bfebf69965edbc86a8a1d4edb4");

		time = Timer.stamp() - time;
		trace("Finished : " + time + " seconds");
	}
}
