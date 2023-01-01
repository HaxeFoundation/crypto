package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.crypto.Murmur1;

class Murmur1Test extends Test
{
	public function test():Void
    {
	    trace("Murmur1 started...");
        var time = Timer.stamp();
		
		eq(Murmur1.hash("Haxe is great!"),2449855428);
		eq(Murmur1.hash("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",0),714747852);
		eq(Murmur1.hash("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",25),595057428);
		eq(Murmur1.hash("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",128),3222482434);
		eq(Murmur1.hash("Haxe can build cross-platform applications."),1292946927	);
		eq(Murmur1.hash(""),0);
		eq(Murmur1.hash("0"),1848692858);
		eq(Murmur1.hash("01"),101741802	);
		eq(Murmur1.hash("012"),562965270);
		eq(Murmur1.hash("0123"),3819071861);
		eq(Murmur1.hash("01234"),3944409);
		eq(Murmur1.hash("012345"),2155193631);
		eq(Murmur1.hash("0123456"),1865278280);
		eq(Murmur1.hash("01234567"),1775700561);
		eq(Murmur1.hash("012345678"),591739721);
		eq(Murmur1.hash("0123456789"),3910874116);
		eq(Murmur1.hash("0123456789a"),4271325040);
		eq(Murmur1.hash("0123456789ab"),1322551924);
		eq(Murmur1.hash("0123456789abc"),1209254348);
		eq(Murmur1.hash("0123456789abcd"),2870758001);
		eq(Murmur1.hash("0123456789abcde"),1816712782);
		eq(Murmur1.hash("0123456789abcdef"),3967912037);
		eq(Murmur1.hash("",1),2405076323);
		
		
		time = Timer.stamp()-time;
        trace("Finished : "+time+" seconds");
	}
}