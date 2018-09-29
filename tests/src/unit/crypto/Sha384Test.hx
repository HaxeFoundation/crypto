package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.crypto.Sha384;

class Sha384Test extends Test
{

    public function test():Void
    {
        trace("Sha384 started...");
        var time = Timer.stamp();

        eq(Sha384.encode(""),"38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
        eq(Sha384.encode("abc"),"cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
        eq(Sha384.encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),"3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");
        eq(Sha384.encode("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),"09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
        eq(Sha384.encode("éあ😂"),"d1d1ece7af1b07ac3c82fe0215dd3b15f7145ae1ccaf30976e49e5c012e5286e0f9bcd5e9c04142c9c98485087ce4d9f");

        time = Timer.stamp()-time;
        trace("Finished : "+time+" seconds");
    }
}
