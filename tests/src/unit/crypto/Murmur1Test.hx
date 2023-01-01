package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.io.Bytes;
import haxe.crypto.Murmur1;

class Murmur1Test extends Test
{
	public function test():Void
    {
	    trace("Murmur1 started...");
        var time = Timer.stamp();
		
		eq(hex(Murmur1.hash(sb("Haxe is great!"))),"9205D3C4");
		eq(hex(Murmur1.hash(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),0)),"2A9A2FCC");
		eq(hex(Murmur1.hash(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),25)),"2377DB14");
		eq(hex(Murmur1.hash(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),128)),"C0132E02");
		eq(hex(Murmur1.hash(sb("Haxe can build cross-platform applications."))),"4D10CDEF");
		eq(hex(Murmur1.hash(sb(""))),"00000000");
		eq(hex(Murmur1.hash(sb("0"))),"6E30D07A");
		eq(hex(Murmur1.hash(sb("01"))),"061074EA");
		eq(hex(Murmur1.hash(sb("012"))),"218E2B16");
		eq(hex(Murmur1.hash(sb("0123"))),"E3A26975");
		eq(hex(Murmur1.hash(sb("01234"))),"003C2FD9");
		eq(hex(Murmur1.hash(sb("012345"))),"8075A51F");
		eq(hex(Murmur1.hash(sb("0123456"))),"6F2DE348");
		eq(hex(Murmur1.hash(sb("01234567"))),"69D70A51");
		eq(hex(Murmur1.hash(sb("012345678"))),"23453B49");
		eq(hex(Murmur1.hash(sb("0123456789"))),"E91B3404");
		eq(hex(Murmur1.hash(sb("0123456789a"))),"FE973F70");
		eq(hex(Murmur1.hash(sb("0123456789ab"))),"4ED48A74");
		eq(hex(Murmur1.hash(sb("0123456789abc"))),"4813C1CC");
		eq(hex(Murmur1.hash(sb("0123456789abcd"))),"AB1C4A71");
		eq(hex(Murmur1.hash(sb("0123456789abcde"))),"6C48D64E");
		eq(hex(Murmur1.hash(sb("0123456789abcdef"))),"EC818865");
		eq(hex(Murmur1.hash(sb(""),1)),"8F5A8D63");
		
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