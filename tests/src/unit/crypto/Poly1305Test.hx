package unit.crypto;

import unit.Test;
import haxe.Timer;
import haxe.io.Bytes;
import haxe.crypto.Poly1305;

class Poly1305Test extends Test {
	var keys = [
		"088EB7C0852E9E5A8905BD272E80F1C0DEFC1B5691CD17A62998CC659EADFF80", "2BA06314CFA36920EBF1D21404179A35E5813D03546E72452349770F67002420",
		"F40495FB5C651BC23016B548467D450CBC57316FB0E2465F8C9A2CD12E9D2B78", "C119FFC3F4357975A338F6AB7B6561698EF95136934D9131790EF26204AE0FFB",
		"FBF5B0465557478634F80D7AC68F3D84722246D4D1076EF2FF15D9128D05D8C5", "B71FE5762CD44F89A37D377931F171F9E7AEF81E754966D82E6BFA427EBFCC27",
		"4C3DFA94816C8A36719AC150D6BD06A260E4535E84885431C425A990C573F682", "F385D13A713E06879204588D6AB09F37A238BA743D30AF73E198D41D788613E0",
		"46C3522EA20587E0A60858B3EFFA1B20954E1BFFC9731A79E38986EC38933C54", "7315DA0DB9035A939A00DFD13B6957BC836CFFADDB05FBAEDFA0EECF53E926AD",
		"92BA2EBFB6BD1768BED19CA6FBA2FE3EDD0B98B5ACE08B50174339B108F65929", "BC1F56AF9DE0DD7C0A2AF3387EA24FC96B986EDFD3A4281DE93E4EE8B6E162AB",
		"41EE904FE16C323F49B5903BC36B7B86536F4DE1C31D30B3C4F4022CED65B869", "F5494FC1A36511C5B80D639ED0467F6D66DEE525CA2923FAC5E82CF0BA052353",
		"0F18CAC3D11A2CDB82EDD80DDF49AE1824E5C3B52E89A47B560C743E34405585", "937F5DFA92144DEADFCB8574989DB66604CDD4DD62434224827F7CE5668576F1",
		"D222025CDFC5A1D3301622D0170F1CC20FE22D267EC6DF8DE73EABB19F01C989", "3FDAB5A0EB57B40E415972E120AC5850E8DA0B7C930365E73FD7EE36FE3D8C5F",
		"D3DC269B7A732F91CEDE53DF0DF76FE11C9500CC6EFEEC9CB0730120C43C183C", "EDD34EA60CAF796E0CB389FA533D6232876F4645B47505F5D46043929A542306"
	];

	var plainText = [
		"",
		"",
		"",
		"",
		"",
		"FD",
		"D9",
		"50",
		"BF",
		"31",
		"F96628C0B07A6BA29BC1A730852CBF3C",
		"EFE538BE25897417828045D0FDFC4C79",
		"F65D4A2300C0FAE131C8F186037A9B84",
		"4799814881D627E8A79E4651D0B553DF",
		"3A12FEB79323F933BCDC2310DC39E616",
		"738798D1260C9B82301732F85B2937BE504703BDD94B3F358EBBF94C026F809509ACFE344412C1E2AA7B91B7BFD97E",
		"CE4E4DA5DFD9FD6ACD44177478BFAE3901600DA5432B43F1F4702CBE1D1399CD2EF8987EAE19BF80A65DE3114F7F9F",
		"774C3A14BF87182735B78A10B265E8DBE90543329B9F28A711FD8429734E03DB2C7ECDA288B369A6C575DF8E154592",
		"D02908581E8E68A90573CADD38778BAA2CBCBB3E457922CFB93DBEAA6FD31D5EB3E93E1A7256C522FC734CC5AC9BEE",
		"8A6BC19BB2309E416BC5F5AD173F782F3A6F74B65B8B0ED8CFAFA484A5EEA7B656453DF5407418E3446D1F1AE0E685"
	];

	var ciphers = [
		"DEFC1B5691CD17A62998CC659EADFF80", "E5813D03546E72452349770F67002420", "BC57316FB0E2465F8C9A2CD12E9D2B78", "8EF95136934D9131790EF26204AE0FFB",
		"722246D4D1076EF2FF15D9128D05D8C5", "D6BD88D4FE241F5C61324F96004C59EF", "CC25AF900D011747C07E5FF67A306B41", "9C07BAA74B23E1ABEA955AA1090FABE1",
		"CF459E014346DD6440A03DC352B51785", "95FAD22E247439ADFB559E0A0E454B61", "FEE792F2D1B14A81142603A94A57505B", "8FEFDAAFEA543178530966264B131E7C",
		"B1E0FDEE3D36699F49ADD1F87BF4EEED", "A12ACE91663939170E2911710827A058", "3495C0198CB81CA90F4DEF72D2C27C6E", "2C95D54D3696721CE4AD9FFAAD099E35",
		"5C02F6660B5BD46A5AE6F3413C889273", "6BFFBBC9D40AD3834DE64FEB18F2FE84", "78994F5223157372AFC5E4C3FC22085A", "C672CF6D2CEFAB4BD551BFCC04716355"
	];

	public function test():Void {
		trace("Poly1305 for " + keys.length + " keys");
		var time = Timer.stamp();
		var poly1305 = new Poly1305();
		for (i in 0...keys.length) {
			var key = Bytes.ofHex(keys[i]);
			var text = Bytes.ofHex(plainText[i]);
			var enc = poly1305.encode(text, key);
			eq(enc.toHex().toUpperCase(), ciphers[i]);
		}
		time = Timer.stamp() - time;
		trace("Finished : " + time + " seconds");
	}
}
