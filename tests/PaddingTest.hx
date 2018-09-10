
import haxe.io.Bytes;
import haxe.crypto.padding.*;

class PaddingTest
{
    var plainText = [
        "0000000000000000", "11111111111111", "222222222222", "3333333333",
        "44444444", "555555", "6666", "77"
       ];

    var pad_ansiX923 = [
        "00000000000000000000000000000008", "1111111111111101", "2222222222220002", "3333333333000003",
        "4444444400000004", "5555550000000005", "6666000000000006","7700000000000007"
        ];

    var pad_bit = [
        "00000000000000008000000000000000", "1111111111111180", "2222222222228000", "3333333333800000",
        "4444444480000000", "5555558000000000", "6666800000000000", "7780000000000000"
        ];

    var pad_random = [
        "0000000000000000C647A5D4DED3D308", "1111111111111101", "222222222222CD02", "3333333333447F03",
        "44444444EE04D204", "555555C5D8A5A605", "66666EEC19E29606", "774DF82706961307"
        ];
    
    var pad_nopad = [
        "0000000000000000", "11111111111111", "222222222222", "3333333333", "44444444", "555555", "6666", "77"
        ];

    var pad_null = [
        "00000000000000000000000000000000", "1111111111111100", "2222222222220000", "3333333333000000",
        "4444444400000000", "5555550000000000", "6666000000000000", "7700000000000000"
        ];

    var pad_pkcs7 = [
        "00000000000000000808080808080808", "1111111111111101", "2222222222220202", "3333333333030303",
        "4444444404040404", "5555550505050505", "6666060606060606", "7707070707070707"
        ];

    var pad_space = [
        "00000000000000002020202020202020", "1111111111111120", "2222222222222020", "3333333333202020",
        "4444444420202020", "5555552020202020", "6666202020202020", "7720202020202020"
        ];

    var pad_tbc = [
        "0000000000000000FFFFFFFFFFFFFFFF", "1111111111111100", "222222222222FFFF", "3333333333000000",
        "44444444FFFFFFFF", "5555550000000000", "6666FFFFFFFFFFFF", "7700000000000000"
        ];

    static inline var BLOCK_SIZE : Int = 8;

    public function new()
    {
        test_pad();
        test_unpad();
    }

    private function checkPading(pad:String,data:Bytes,type:Padding):Void
    {
        if ( pad !=  data.toHex().toUpperCase() ) throw "Wrong padding "+type+" . Got "+data.toHex().toUpperCase()+" expected "+pad;
           
    }

    public function test_pad():Void
    {
        for(i in 0...plainText.length)
        {
           var padAnsiX923 = AnsiX923.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
           checkPading(pad_ansiX923[i],padAnsiX923,Padding.AnsiX923);
           var padBit = BitPadding.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
           checkPading(pad_bit[i],padBit,Padding.BitPadding);
           var padIso10126 = ISO10126.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE); //not check, random bytes
           var padNoPadding = NoPadding.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
           checkPading(pad_nopad[i],padNoPadding,Padding.NoPadding);
           var padNull = NullPadding.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
           checkPading(pad_null[i],padNull,Padding.NullPadding);
           var padPkcs7 = PKCS7.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
           checkPading(pad_pkcs7[i],padPkcs7,Padding.PKCS7);
           var padSpace = SpacePadding.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
           checkPading(pad_space[i],padSpace,Padding.SpacePadding);
           var padTbc = TBC.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
           checkPading(pad_tbc[i],padTbc,Padding.TBC);
        }
    }

    public function test_unpad():Void
    {
        for(i in 0...plainText.length)
        {
           var padAnsiX923 = AnsiX923.unpad(Bytes.ofHex(pad_ansiX923[i]));
           checkPading(plainText[i],padAnsiX923,Padding.AnsiX923);
           var padBit = BitPadding.unpad(Bytes.ofHex(pad_bit[i]));
           checkPading(plainText[i],padBit,Padding.BitPadding);
           var padIso10126 = ISO10126.unpad(Bytes.ofHex(pad_random[i]));
           checkPading(plainText[i],padIso10126,Padding.ISO10126);
           var padNoPadding = NoPadding.unpad(Bytes.ofHex(pad_nopad[i]));
           checkPading(plainText[i],padNoPadding,Padding.NoPadding);
           if ( i != 0) //skip check on 00 bytes
           { 
            var padNull = NullPadding.unpad(Bytes.ofHex(pad_null[i]));
            checkPading(plainText[i],padNull,Padding.NullPadding);
           }
           var padPkcs7 = PKCS7.unpad(Bytes.ofHex(pad_pkcs7[i]));
           checkPading(plainText[i],padPkcs7,Padding.PKCS7);
           var padSpace = SpacePadding.unpad(Bytes.ofHex(pad_space[i]));
           checkPading(plainText[i],padSpace,Padding.SpacePadding);
           var padTbc = TBC.unpad(Bytes.ofHex(pad_tbc[i]));
           checkPading(plainText[i],padTbc,Padding.TBC);
        }
    }
}