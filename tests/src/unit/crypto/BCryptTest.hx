package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.crypto.BCrypt;

class BCryptTest extends Test
{
    private function test():Void
    {
        trace("Bcrypt started ...");
        var time = Timer.stamp();
        eq(BCrypt.encode("password","$2a$05$bvIG6Nmid91Mu9RcmmWZfO"), "$2a$05$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe" );
        eq(BCrypt.encode("","$2b$10$wZ.uNrpCdxqrD/btVW9soe"), "$2b$10$wZ.uNrpCdxqrD/btVW9soe6bpm0kAXneRfcovqH1BWlTIPmwgZXgC");
        eq(BCrypt.encode("The quick brown fox jumps over the lazy dog","$2a$10$//pCfnG5nwASrIRZg9.hN."), "$2a$10$//pCfnG5nwASrIRZg9.hN.kj7o2mHEC5cQPOc4fdSySYsD2kFfH1K");
        eq(BCrypt.encode("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq","$2a$10$mwU8XJBYYrH2Q8oVIqFwtO"), "$2a$10$mwU8XJBYYrH2Q8oVIqFwtOzHvUpHV7Dd.q0BQxAtXGzUPyV97XucW");
        eq(BCrypt.encode("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu","$2b$10$rSrrYyKkUelbA1ymx7SWsu"), "$2b$10$rSrrYyKkUelbA1ymx7SWsuseD6.vdEvEyZyrGLyUuBzItVbFqthN2");
        time = Timer.stamp()-time;
        trace("Finished : "+time+" seconds");
    }
}
