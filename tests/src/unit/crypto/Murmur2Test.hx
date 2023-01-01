package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.crypto.Murmur2;

class Murmur2Test extends Test
{
	public function test():Void
    {
	    trace("Murmur2 started...");
        var time = Timer.stamp();
		
		eq(Murmur2.hash("Haxe is great!"),146417629);
		eq(Murmur2.hash("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",0),22188215);
		eq(Murmur2.hash("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",25),1223534370);
		eq(Murmur2.hash("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",128),3904177038);
		eq(Murmur2.hash("Haxe can build cross-platform applications."),1436453795);
		eq(Murmur2.hash(""),0);
		eq(Murmur2.hash("0"),1111412596);
		eq(Murmur2.hash("01"),3879298654);
		eq(Murmur2.hash("012"),2151403590);
		eq(Murmur2.hash("0123"),3708114270);
		eq(Murmur2.hash("01234"),2096888684);
		eq(Murmur2.hash("012345"),4012604407);
		eq(Murmur2.hash("0123456"),1229863857);
		eq(Murmur2.hash("01234567"),4120441554);
		eq(Murmur2.hash("012345678"),933333739);
		eq(Murmur2.hash("0123456789"),439272720);
		eq(Murmur2.hash("0123456789a"),605940346);
		eq(Murmur2.hash("0123456789ab"),123333918);
		eq(Murmur2.hash("0123456789abc"),1712711356);
		eq(Murmur2.hash("0123456789abcd"),3603314196);
		eq(Murmur2.hash("0123456789abcde"),413768642);
		eq(Murmur2.hash("0123456789abcdef"),3483039514);
		eq(Murmur2.hash("",1),1540447798);
		
		eq(Murmur2.hash64("Haxe is great!"),"ee74b2fb0fc244ff");
		eq(Murmur2.hash64("Haxe can build cross-platform applications."),"9169a7a812eeb761");
		eq(Murmur2.hash64("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",0),"ec2967295e0ff57d");
		eq(Murmur2.hash64("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",25),"873cc870616c012a");
		eq(Murmur2.hash64("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",128),"43fafd38eef05dda");
		eq(Murmur2.hash64(""),"0000000000000000");
		eq(Murmur2.hash64("0"),"4ccb322c4bcf1d63");
		eq(Murmur2.hash64("01"),"2978efdda2b851bf");
		eq(Murmur2.hash64("012"),"fb7b9e0e9e60cf09");
		eq(Murmur2.hash64("0123"),"2ad4bd22814486a0");
		eq(Murmur2.hash64("01234"),"abb764366512b1a6");
		eq(Murmur2.hash64("012345"),"6f8a70652cc3e70f");
		eq(Murmur2.hash64("0123456"),"aa7bcb1cbf86f7c6");
		eq(Murmur2.hash64("01234567"),"87b47e2a5e55a79a");
		eq(Murmur2.hash64("012345678"),"c0490f312ff95ca");
		eq(Murmur2.hash64("0123456789"),"a8247417c7909865");
		eq(Murmur2.hash64("0123456789a"),"3cdbf3bd40107e43");
		eq(Murmur2.hash64("0123456789ab"),"a739e22064444dfa");
		eq(Murmur2.hash64("0123456789abc"),"b4878699f9f1b9c5");
		eq(Murmur2.hash64("0123456789abcd"),"584ea4319e4e3fb7");
		eq(Murmur2.hash64("0123456789abcde"),"89ecff3076295665");
		eq(Murmur2.hash64("0123456789abcdef"),"93a92d1a91a24bc7");
		eq(Murmur2.hash64("",1),"c6a4a7935bd064dc");
		
		time = Timer.stamp()-time;
        trace("Finished : "+time+" seconds");
	}
}