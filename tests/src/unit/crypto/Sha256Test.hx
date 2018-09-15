package unit.crypto;

import unit.Test;
import haxe.io.Bytes;
import haxe.crypto.Sha256;

class Sha256Test extends Test
{

    public function test_hash_sha256():Void
    {
       eq(Sha256.encode(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	   eq(Sha256.encode("The quick brown fox jumps over the lazy dog"), "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
	   eq(Sha256.encode("éあ😂"), "d0230b8d8ac2d6d0dbcee11ad0e0eaa68a6565347261871dc241571cab591676");
    }
}
