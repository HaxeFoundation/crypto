package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.crypto.Murmur3;

class Murmur3Test extends Test
{
	public function test():Void
    {
	    trace("Murmur3 started...");
        var time = Timer.stamp();
		
		eq(Murmur3.hash("Haxe is great!"),2086637627);
		eq(Murmur3.hash("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",0),2068081906);
		eq(Murmur3.hash("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",25),2386375015);
		eq(Murmur3.hash("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",128),3836537046);
		eq(Murmur3.hash("Haxe can build cross-platform applications."),2309495466);
		eq(Murmur3.hash(""),0);
		eq(Murmur3.hash("0"),3530670207);
		eq(Murmur3.hash("01"),1642882560);
		eq(Murmur3.hash("012"),3966566284);
		eq(Murmur3.hash("0123"),3558446240);
		eq(Murmur3.hash("01234"),433070448);
		eq(Murmur3.hash("012345"),1898502397);
		eq(Murmur3.hash("0123456"),183447976);
		eq(Murmur3.hash("01234567"),1451431763);
		eq(Murmur3.hash("012345678"),1350687357);
		eq(Murmur3.hash("0123456789"),1891213601);
		eq(Murmur3.hash("0123456789a"),3564907726);
		eq(Murmur3.hash("0123456789ab"),2044149191);
		eq(Murmur3.hash("0123456789abc"),4193546897);
		eq(Murmur3.hash("0123456789abcd"),439890777);
		eq(Murmur3.hash("0123456789abcde"),2250527230);
		eq(Murmur3.hash("0123456789abcdef"),919068895);
		eq(Murmur3.hash("",1),1364076727);
		
		eq(Murmur3.hash128("Haxe is great!"),"1D6677A5728BDB846E81B7EDDD7853C3");
		eq(Murmur3.hash128("Haxe can build cross-platform applications."),"c3ee8a798db1c9e7dae96d05dbcd647d");
		eq(Murmur3.hash128("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",0),"a44424f6365965981fb15205bd1e9d0");
		eq(Murmur3.hash128("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",25),"72bc742e94ef6eeb2c77f5dcef49f039");
		eq(Murmur3.hash128("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler.",128),"6ac57ac5129fba9f2734ecf3d2fbee35");
		eq(Murmur3.hash128(""),"00000000000000000000000000000000");
		eq(Murmur3.hash128("0"),"2ac9debed546a3803a8de9e53c875e09");
		eq(Murmur3.hash128("01"),"649e4eaa7fc1708ee6945110230f2ad6");
		eq(Murmur3.hash128("012"),"ce68f60d7c353bdb00364cd5936bf18a");
		eq(Murmur3.hash128("0123"),"0f95757ce7f38254b4c67c9e6f12ab4b");
		eq(Murmur3.hash128("01234"),"0f04e459497f3fc1eccc6223a28dd613");
		eq(Murmur3.hash128("012345"),"88c0a92586be0a2781062d6137728244");
		eq(Murmur3.hash128("0123456"),"13eb9fb82606f7a6b4ebef492fdef34e");
		eq(Murmur3.hash128("01234567"),"8236039b7387354dc3369387d8964920");
		eq(Murmur3.hash128("012345678"),"4c1e87519fe738ba72a17af899d597f1");
		eq(Murmur3.hash128("0123456789"),"3f9652ac3effeb248027a17cf2990b07");
		eq(Murmur3.hash128("0123456789a"),"4bc3eacd29d386297cb2d9e797da9c92");
		eq(Murmur3.hash128("0123456789ab"),"66352b8cee9e3ca7a9edf0b381a8fc58");
		eq(Murmur3.hash128("0123456789abc"),"5eb2f8db4265931e801ce853e61d0ab7");
		eq(Murmur3.hash128("0123456789abcd"),"07a4a014dd59f71aaaf437854cd22231");
		eq(Murmur3.hash128("0123456789abcde"),"a62dd5f6c0bf23514fccf50c7c544cf0");
		eq(Murmur3.hash128("0123456789abcdef"),"4be06d94cf4ad1a787c35b5c63a708da");
		eq(Murmur3.hash128("",1),"4610abe56eff5cb551622daa78f83583");
		
		eq(Murmur3.hash128_x86("Haxe is great!"),"3a29b9fb17f64971688b71411a60963c");
		eq(Murmur3.hash128_x86(""),"00000000000000000000000000000000");
		eq(Murmur3.hash128_x86("0"),"0ab2409ea5eb34f8a5eb34f8a5eb34f8");
		eq(Murmur3.hash128_x86("01"),"0f87acb4674f3b21674f3b21674f3b21");
		eq(Murmur3.hash128_x86("012"),"cd94fea54c13d78e4c13d78e4c13d78e");
		eq(Murmur3.hash128_x86("0123"),"dc378fea485d3536485d3536485d3536");
		eq(Murmur3.hash128_x86("01234"),"35c5b3ee7b3b211600ae108800ae1088");
		eq(Murmur3.hash128_x86("012345"),"db26dc756ce1944bf825536af825536a");
		eq(Murmur3.hash128_x86("0123456"),"b708d0a186d15c02495d053b495d053b");
		eq(Murmur3.hash128_x86("01234567"),"aa22bf849216040263b83c5e63b83c5e");
		eq(Murmur3.hash128_x86("012345678"),"571b5f6775d48126d0205c304ca675dc");
		eq(Murmur3.hash128_x86("0123456789"),"0017a61e2e528b33a5443f2057a11235");
		eq(Murmur3.hash128_x86("0123456789a"),"38a2ed0f921f15e42caa7f97a971884f");
		eq(Murmur3.hash128_x86("0123456789ab"),"cfaa93f9b6982a7e53412b5d04d3d08f");
		eq(Murmur3.hash128_x86("0123456789abc"),"c970af1dcc6d9d01dd00c683fc11eee3");
		eq(Murmur3.hash128_x86("0123456789abcd"),"6f34d20ac0a5114dae0d83c563f51794");
		eq(Murmur3.hash128_x86("0123456789abcde"),"3c76c46d4d0818c0add433daa78673fa");
		eq(Murmur3.hash128_x86("0123456789abcdef"),"fb7d440936aed30a48ad1d9b572b3bfd");
		eq(Murmur3.hash128_x86("",1),"88c4adec54d201b954d201b954d201b9");
		
		var murmur3:Murmur3 = new Murmur3();
        murmur3.addString('0').addString('1').addString('2');
		eq(murmur3.result(),3966566284);
		murmur3.reset().addString("Haxe is great!");
		eq(murmur3.result(),2086637627);
		murmur3.reset(1).addString("");
		eq(murmur3.result(),1364076727);
		
		
		time = Timer.stamp()-time;
        trace("Finished : "+time+" seconds");
	}
}