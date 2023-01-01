package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.io.Bytes;
import haxe.crypto.Murmur3;

class Murmur3Test extends Test
{
	public function test():Void
    {
	    trace("Murmur3 started...");
        var time = Timer.stamp();
		
		eq(hex(Murmur3.hash(sb("Haxe is great!"))),"7C5F903B");
		eq(hex(Murmur3.hash(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),0)),"7B446CF2");
		eq(hex(Murmur3.hash(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),25)),"8E3D3167");
		eq(hex(Murmur3.hash(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),128)),"E4ACE8D6");
		eq(hex(Murmur3.hash(sb("Haxe can build cross-platform applications."))),"89A81AAA");
		eq(hex(Murmur3.hash(sb(""))),"00000000");
		eq(hex(Murmur3.hash(sb("0"))),"D271C07F");
		eq(hex(Murmur3.hash(sb("01"))),"61EC6600");
		eq(hex(Murmur3.hash(sb("012"))),"EC6CFF8C");
		eq(hex(Murmur3.hash(sb("0123"))),"D41994A0");
		eq(hex(Murmur3.hash(sb("01234"))),"19D02170");
		eq(hex(Murmur3.hash(sb("012345"))),"7128D8FD");
		eq(hex(Murmur3.hash(sb("0123456"))),"0AEF31A8");
		eq(hex(Murmur3.hash(sb("01234567"))),"56831753");
		eq(hex(Murmur3.hash(sb("012345678"))),"5081DA7D");
		eq(hex(Murmur3.hash(sb("0123456789"))),"70B9A121");
		eq(hex(Murmur3.hash(sb("0123456789a"))),"D47C2CCE");
		eq(hex(Murmur3.hash(sb("0123456789ab"))),"79D73DC7");
		eq(hex(Murmur3.hash(sb("0123456789abc"))),"F9F47291");
		eq(hex(Murmur3.hash(sb("0123456789abcd"))),"1A383359");
		eq(hex(Murmur3.hash(sb("0123456789abcde"))),"862451FE");
		eq(hex(Murmur3.hash(sb("0123456789abcdef"))),"36C7E0DF");
		eq(hex(Murmur3.hash(sb(""),1)),"514E28B7");
		
		eq(Murmur3.hash128(sb("Haxe is great!")),"1D6677A5728BDB846E81B7EDDD7853C3");
		eq(Murmur3.hash128(sb("Haxe can build cross-platform applications.")),"C3EE8A798DB1C9E7DAE96D05DBCD647D");
		eq(Murmur3.hash128(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),0),"A44424F63659659801FB15205BD1E9D0");
		eq(Murmur3.hash128(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),25),"72BC742E94EF6EEB2C77F5DCEF49F039");
		eq(Murmur3.hash128(sb("Haxe is an open source high-level strictly-typed programming language with a fast optimizing cross-compiler."),128),"6AC57AC5129FBA9F2734ECF3D2FBEE35");
		eq(Murmur3.hash128(sb("")),"00000000000000000000000000000000");
		eq(Murmur3.hash128(sb("0")),"2AC9DEBED546A3803A8DE9E53C875E09");
		eq(Murmur3.hash128(sb("01")),"649E4EAA7FC1708EE6945110230F2AD6");
		eq(Murmur3.hash128(sb("012")),"CE68F60D7C353BDB00364CD5936BF18A");
		eq(Murmur3.hash128(sb("0123")),"0F95757CE7F38254B4C67C9E6F12AB4B");
		eq(Murmur3.hash128(sb("01234")),"0F04E459497F3FC1ECCC6223A28DD613");
		eq(Murmur3.hash128(sb("012345")),"88C0A92586BE0A2781062D6137728244");
		eq(Murmur3.hash128(sb("0123456")),"13EB9FB82606F7A6B4EBEF492FDEF34E");
		eq(Murmur3.hash128(sb("01234567")),"8236039B7387354DC3369387D8964920");
		eq(Murmur3.hash128(sb("012345678")),"4C1E87519FE738BA72A17AF899D597F1");
		eq(Murmur3.hash128(sb("0123456789")),"3F9652AC3EFFEB248027A17CF2990B07");
		eq(Murmur3.hash128(sb("0123456789a")),"4BC3EACD29D386297CB2D9E797DA9C92");
		eq(Murmur3.hash128(sb("0123456789ab")),"66352B8CEE9E3CA7A9EDF0B381A8FC58");
		eq(Murmur3.hash128(sb("0123456789abc")),"5EB2F8DB4265931E801CE853E61D0AB7");
		eq(Murmur3.hash128(sb("0123456789abcd")),"07A4A014DD59F71AAAF437854CD22231");
		eq(Murmur3.hash128(sb("0123456789abcde")),"A62DD5F6C0BF23514FCCF50C7C544CF0");
		eq(Murmur3.hash128(sb("0123456789abcdef")),"4BE06D94CF4AD1A787C35B5C63A708DA");
		eq(Murmur3.hash128(sb(""),1),"4610ABE56EFF5CB551622DAA78F83583");
		
		eq(Murmur3.hash128_x86(sb("Haxe is great!")),"3A29B9FB17F64971688B71411A60963C");
		eq(Murmur3.hash128_x86(sb("")),"00000000000000000000000000000000");
		eq(Murmur3.hash128_x86(sb("0")),"0AB2409EA5EB34F8A5EB34F8A5EB34F8");
		eq(Murmur3.hash128_x86(sb("01")),"0F87ACB4674F3B21674F3B21674F3B21");
		eq(Murmur3.hash128_x86(sb("012")),"CD94FEA54C13D78E4C13D78E4C13D78E");
		eq(Murmur3.hash128_x86(sb("0123")),"DC378FEA485D3536485D3536485D3536");
		eq(Murmur3.hash128_x86(sb("01234")),"35C5B3EE7B3B211600AE108800AE1088");
		eq(Murmur3.hash128_x86(sb("012345")),"DB26DC756CE1944BF825536AF825536A");
		eq(Murmur3.hash128_x86(sb("0123456")),"B708D0A186D15C02495D053B495D053B");
		eq(Murmur3.hash128_x86(sb("01234567")),"AA22BF849216040263B83C5E63B83C5E");
		eq(Murmur3.hash128_x86(sb("012345678")),"571B5F6775D48126D0205C304CA675DC");
		eq(Murmur3.hash128_x86(sb("0123456789")),"0017A61E2E528B33A5443F2057A11235");
		eq(Murmur3.hash128_x86(sb("0123456789a")),"38A2ED0F921F15E42CAA7F97A971884F");
		eq(Murmur3.hash128_x86(sb("0123456789ab")),"CFAA93F9B6982A7E53412B5D04D3D08F");
		eq(Murmur3.hash128_x86(sb("0123456789abc")),"C970AF1DCC6D9D01DD00C683FC11EEE3");
		eq(Murmur3.hash128_x86(sb("0123456789abcd")),"6F34D20AC0A5114DAE0D83C563F51794");
		eq(Murmur3.hash128_x86(sb("0123456789abcde")),"3C76C46D4D0818C0ADD433DAA78673FA");
		eq(Murmur3.hash128_x86(sb("0123456789abcdef")),"FB7D440936AED30A48AD1D9B572B3BFD");
		eq(Murmur3.hash128_x86(sb(""),1),"88C4ADEC54D201B954D201B954D201B9");
		
		var murmur3:Murmur3 = new Murmur3();
        murmur3.addString('0').addString('1').addString('2');
		eq(hex(murmur3.result()),"EC6CFF8C");
		murmur3.reset().addString("Haxe is great!");
		eq(hex(murmur3.result()),"7C5F903B");
		murmur3.reset(1).addString("");
		eq(hex(murmur3.result()),"514E28B7");
		
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