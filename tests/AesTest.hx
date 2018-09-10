import haxe.Timer;
import haxe.io.Bytes;
import haxe.crypto.AES;
import haxe.crypto.mode.Mode;
import haxe.crypto.padding.*;

class AesTest
{
    var keys = [
            "2B7E151628AED2A6ABF7158809CF4F3C", "2B7E151628AED2A6ABF7158809CF4F3C", "2B7E151628AED2A6ABF7158809CF4F3C", "2B7E151628AED2A6ABF7158809CF4F3C",
            "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B", "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B", "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B", "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B",
            "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4"
        ];
    
    var plainText = [
            "6BC1BEE22E409F96E93D7E117393172A", "AE2D8A571E03AC9C9EB76FAC45AF8E51", "30C81C46A35CE411E5FBC1191A0A52EF", "F69F2445DF4F9B17AD2B417BE66C3710",
            "6BC1BEE22E409F96E93D7E117393172A", "AE2D8A571E03AC9C9EB76FAC45AF8E51", "30C81C46A35CE411E5FBC1191A0A52EF", "F69F2445DF4F9B17AD2B417BE66C3710",
            "6BC1BEE22E409F96E93D7E117393172A", "AE2D8A571E03AC9C9EB76FAC45AF8E51", "30C81C46A35CE411E5FBC1191A0A52EF", "F69F2445DF4F9B17AD2B417BE66C3710"
        ];

    var ecb_ciphers = [
            "3AD77BB40D7A3660A89ECAF32466EF97", "F5D3D58503B9699DE785895A96FDBAAF", "43B1CD7F598ECE23881B00E3ED030688", "7B0C785E27E8AD3F8223207104725DD4",
            "BD334F1D6E45F25FF712A214571FA5CC", "974104846D0AD3AD7734ECB3ECEE4EEF", "EF7AFD2270E2E60ADCE0BA2FACE6444E", "9A4B41BA738D6C72FB16691603C18E0E",
            "F3EED1BDB5D2A03C064B5A7E3DB181F8", "591CCB10D410ED26DC5BA74A31362870", "B6ED21B99CA6F4F9F153E7B1BEAFED1D", "23304B7A39F9F3FF067D8D8F9E24ECC7"
        ];
    
    var cbc_iv = [
            "000102030405060708090A0B0C0D0E0F", "7649ABAC8119B246CEE98E9B12E9197D", "5086CB9B507219EE95DB113A917678B2", "73BED6B8E3C1743B7116E69E22229516",
            "000102030405060708090A0B0C0D0E0F", "4F021DB243BC633D7178183A9FA071E8", "B4D9ADA9AD7DEDF4E5E738763F69145A", "571B242012FB7AE07FA9BAAC3DF102E0",
            "000102030405060708090A0B0C0D0E0F", "F58C4C04D6E5F1BA779EABFB5F7BFBD6", "9CFC4E967EDB808D679F777BC6702C7D", "39F23369A9D9BACFA530E26304231461"
    ];

    var cbc_ciphers = [
            "7649ABAC8119B246CEE98E9B12E9197D", "5086CB9B507219EE95DB113A917678B2", "73BED6B8E3C1743B7116E69E22229516", "3FF1CAA1681FAC09120ECA307586E1A7",
            "4F021DB243BC633D7178183A9FA071E8", "B4D9ADA9AD7DEDF4E5E738763F69145A", "571B242012FB7AE07FA9BAAC3DF102E0", "08B0E27988598881D920A9E64F5615CD",
            "F58C4C04D6E5F1BA779EABFB5F7BFBD6", "9CFC4E967EDB808D679F777BC6702C7D", "39F23369A9D9BACFA530E26304231461", "B2EB05E2C39BE9FCDA6C19078C6A9D1B"
    ];

    var cfb_iv = [
            "000102030405060708090A0B0C0D0E0F", "3B3FD92EB72DAD20333449F8E83CFB4A", "C8A64537A0B3A93FCDE3CDAD9F1CE58B", "26751F67A3CBB140B1808CF187A4F4DF",
            "000102030405060708090A0B0C0D0E0F", "CDC80D6FDDF18CAB34C25909C99A4174", "67CE7F7F81173621961A2B70171D3D7A", "2E1E8A1DD59B88B1C8E60FED1EFAC4C9",
            "000102030405060708090A0B0C0D0E0F", "DC7E84BFDA79164B7ECD8486985D3860", "39FFED143B28B1C832113C6331E5407B", "DF10132415E54B92A13ED0A8267AE2F9"
    ];

    var cfb_ciphers = [
            "3B3FD92EB72DAD20333449F8E83CFB4A", "C8A64537A0B3A93FCDE3CDAD9F1CE58B", "26751F67A3CBB140B1808CF187A4F4DF", "C04B05357C5D1C0EEAC4C66F9FF7F2E6",
            "CDC80D6FDDF18CAB34C25909C99A4174", "67CE7F7F81173621961A2B70171D3D7A", "2E1E8A1DD59B88B1C8E60FED1EFAC4C9", "C05F9F9CA9834FA042AE8FBA584B09FF",
            "DC7E84BFDA79164B7ECD8486985D3860", "39FFED143B28B1C832113C6331E5407B", "DF10132415E54B92A13ED0A8267AE2F9", "75A385741AB9CEF82031623D55B1E471"
    ];

    var ofb_iv = [
            "000102030405060708090A0B0C0D0E0F", "50FE67CC996D32B6DA0937E99BAFEC60", "D9A4DADA0892239F6B8B3D7680E15674", "A78819583F0308E7A6BF36B1386ABF23", 
            "000102030405060708090A0B0C0D0E0F", "A609B38DF3B1133DDDFF2718BA09565E", "52EF01DA52602FE0975F78AC84BF8A50", "BD5286AC63AABD7EB067AC54B553F71D",
            "000102030405060708090A0B0C0D0E0F", "B7BF3A5DF43989DD97F0FA97EBCE2F4A", "E1C656305ED1A7A6563805746FE03EDC", "41635BE625B48AFC1666DD42A09D96E7"
    ];

    var ofb_ciphers = [
            "3B3FD92EB72DAD20333449F8E83CFB4A", "7789508D16918F03F53C52DAC54ED825", "9740051E9C5FECF64344F7A82260EDCC", "304C6528F659C77866A510D9C1D6AE5E",
            "CDC80D6FDDF18CAB34C25909C99A4174", "FCC28B8D4C63837C09E81700C1100401", "8D9A9AEAC0F6596F559C6D4DAF59A5F2", "6D9F200857CA6C3E9CAC524BD9ACC92A",
            "DC7E84BFDA79164B7ECD8486985D3860", "4FEBDC6740D20B3AC88F6AD82A4FB08D", "71AB47A086E86EEDF39D1C5BBA97C408", "0126141D67F37BE8538F5A8BE740E484"
    ];

    public function new() 
    {
        trace("Aes starts...");
        test_ecb();
        test_cbc();
        test_cfb();
        test_ofb();
    }

    public function test_ecb():Void
    {
        test(ecb_ciphers,Mode.ECB,Padding.NoPadding,null);
    }

    public function test_cbc():Void
    {
        test(cbc_ciphers,Mode.CBC,Padding.NoPadding,cbc_iv);
    }

    public function test_cfb():Void
    {
        test(cfb_ciphers,Mode.CFB,Padding.NoPadding,cfb_iv);
    }

    public function test_ofb():Void
    {
        test(ofb_ciphers,Mode.OFB,Padding.NoPadding,ofb_iv);
    }

    public function test(ciphers:Array<String>, cipherMode:Mode, padding:Padding, ivTable:Array<String>):Void
    {
        trace("Starting "+cipherMode+" mode for "+keys.length+" keys");
        var time = Timer.stamp();
        
        var aes : AES = new AES();

        for(i in 0...keys.length)
        {
            var key = Bytes.ofHex(keys[i]);
            var text = Bytes.ofHex(plainText[i]);
            var iv:Bytes = (ivTable == null)?null:Bytes.ofHex(ivTable[i]);
            aes.init(key,iv);
            var enc = aes.encrypt(cipherMode,text,padding);
            if ( enc.toHex().toUpperCase() != ciphers[i] ) throw "Wrong Aes encryption for "+plainText[i]+", expected "+ciphers[i]+" got "+enc.toHex()+" , mode: "+cipherMode;
            var decr = aes.decrypt(cipherMode,enc,padding);
            if ( decr.toHex().toUpperCase() != plainText[i] ) throw "Wrong Aes decryption for "+enc.toHex()+", expected "+plainText[i]+" got "+decr.toHex()+" , mode: "+cipherMode;
        }
        
        time = Timer.stamp()-time;
        trace("Finished : "+time+" seconds");
    }
}