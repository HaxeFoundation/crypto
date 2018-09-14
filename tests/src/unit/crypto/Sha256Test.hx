package unit.crypto;

import unit.Test;
import haxe.io.Bytes;
import haxe.crypto.Sha256;

class Sha256Test extends Test
{

    public function test_encrypt():Void
    {
       eq(haxe.crypto.Sha256.encode(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    public function test_decrypt():Void
    {
      eq(haxe.crypto.Sha256.encode("The quick brown fox jumps over the lazy dog"), "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
    }
}
