package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.io.Bytes;
import haxe.crypto.Murmur2;

class Murmur2Test extends Test
{
	public function test():Void
    {
	    trace("Murmur2 started...");
        var time = Timer.stamp();
		
        eq(hex(Murmur2.hash(sb("Haxe is great!"))),"08BA27DD");
        eq(hex(Murmur2.hash(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),0)),"015290B7");
        eq(hex(Murmur2.hash(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),25)),"48EDA722");
        eq(hex(Murmur2.hash(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),128)),"E8B5038E");
        eq(hex(Murmur2.hash(sb("Haxe can build cross-platform applications."))),"559E8BA3");
        eq(hex(Murmur2.hash(sb(""))),"00000000");
        eq(hex(Murmur2.hash(sb("0"))),"423ECF74");
        eq(hex(Murmur2.hash(sb("01"))),"E739665E");
        eq(hex(Murmur2.hash(sb("012"))),"803BD046");
        eq(hex(Murmur2.hash(sb("0123"))),"DD05555E");
        eq(hex(Murmur2.hash(sb("01234"))),"7CFBFB6C");
        eq(hex(Murmur2.hash(sb("012345"))),"EF2B7BF7");
        eq(hex(Murmur2.hash(sb("0123456"))),"494E3BB1");
        eq(hex(Murmur2.hash(sb("01234567"))),"F598F2D2");
        eq(hex(Murmur2.hash(sb("012345678"))),"37A18AEB");
        eq(hex(Murmur2.hash(sb("0123456789"))),"1A2EC510");
        eq(hex(Murmur2.hash(sb("0123456789a"))),"241DEA7A");
        eq(hex(Murmur2.hash(sb("0123456789ab"))),"0759ED1E");
        eq(hex(Murmur2.hash(sb("0123456789abc"))),"6615E6BC");
        eq(hex(Murmur2.hash(sb("0123456789abcd"))),"D6C63614");
        eq(hex(Murmur2.hash(sb("0123456789abcde"))),"18A99BC2");
        eq(hex(Murmur2.hash(sb("0123456789abcdef"))),"CF9AF71A");
        eq(hex(Murmur2.hash(sb(""),1)),"5BD15E36");
            
        eq(Murmur2.hash64(sb("Haxe is great!")),"EE74B2FB0FC244FF");
        eq(Murmur2.hash64(sb("Haxe can build cross-platform applications.")),"9169A7A812EEB761");
        eq(Murmur2.hash64(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),0),"EC2967295E0FF57D");
        eq(Murmur2.hash64(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),25),"873CC870616C012A");
        eq(Murmur2.hash64(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),128),"43FAFD38EEF05DDA");
        eq(Murmur2.hash64(sb("")),"0000000000000000");
        eq(Murmur2.hash64(sb("0")),"4CCB322C4BCF1D63");
        eq(Murmur2.hash64(sb("01")),"2978EFDDA2B851BF");
        eq(Murmur2.hash64(sb("012")),"FB7B9E0E9E60CF09");
        eq(Murmur2.hash64(sb("0123")),"2AD4BD22814486A0");
        eq(Murmur2.hash64(sb("01234")),"ABB764366512B1A6");
        eq(Murmur2.hash64(sb("012345")),"6F8A70652CC3E70F");
        eq(Murmur2.hash64(sb("0123456")),"AA7BCB1CBF86F7C6");
        eq(Murmur2.hash64(sb("01234567")),"87B47E2A5E55A79A");
        eq(Murmur2.hash64(sb("012345678")),"0C0490F312FF95CA");
        eq(Murmur2.hash64(sb("0123456789")),"A8247417C7909865");
        eq(Murmur2.hash64(sb("0123456789a")),"3CDBF3BD40107E43");
        eq(Murmur2.hash64(sb("0123456789ab")),"A739E22064444DFA");
        eq(Murmur2.hash64(sb("0123456789abc")),"B4878699F9F1B9C5");
        eq(Murmur2.hash64(sb("0123456789abcd")),"584EA4319E4E3FB7");
        eq(Murmur2.hash64(sb("0123456789abcde")),"89ECFF3076295665");
        eq(Murmur2.hash64(sb("0123456789abcdef")),"93A92D1A91A24BC7");
        eq(Murmur2.hash64(sb(""),1),"C6A4A7935BD064DC");
		
		time = Timer.stamp()-time;
        trace("Finished : "+time+" seconds");
	}
	
	public function sb(s:String):Bytes
	{
		return Bytes.ofString(s);
	}
	
	public function hex(v:UInt):String
	{
		return StringTools.hex(v,8);
	}
}