package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.io.Bytes;
import haxe.crypto.Ripemd160;

class Ripemd160Test extends Test
{
    var hashes = [
            "9c1185a5c5e9fc54612808977ee8f548b2258d31", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
			"5d0689ef49d2fae572b881b123a85ffa21595f36", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc", "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
			"b0e20b6e3116640286ed3a87a5713079b21f5189","9b752e45573d4b39f4dbd3323cab82bf63326bfb","e6f95b697f98c944e6234a6313e11e179c8e867c",
			"5f5b48448f5e0abab49da46b9c8c0b0395eac519"
        ];
    var plainText = [
            "", "a", "abc", "message digest","abcdefghijklmnopqrstuvwxyz","abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789","12345678901234567890123456789012345678901234567890123456789012345678901234567890",
			"Sed ut perspiciatis unde omnis iste natus error sit vol",
            "Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia"
        ];

    public function test():Void
    {
        trace("Ripemd160 mode for "+hashes.length+" hashes");
        var time = Timer.stamp();

        for(i in 0...plainText.length)
        {
            var enc = Ripemd160.encode(plainText[i]);
            eq( enc, hashes[i] );
        }

        time = Timer.stamp()-time;
        trace("Finished : "+time+" seconds");
    }
}
