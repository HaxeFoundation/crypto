package unit.crypto;

import unit.Test;
import haxe.io.Bytes;
import haxe.crypto.mode.*;

class ModeTest extends Test
{
     var plainText = [
        "6BC1BEE22E409F96E93D7E117393172A", "AE2D8A571E03AC9C9EB76FAC45AF8E51", "30C81C46A35CE411E5FBC1191A0A52EF", "F69F2445DF4F9B17AD2B417BE66C3710",
        "6BC1BEE22E409F96E93D7E117393172A", "AE2D8A571E03AC9C9EB76FAC45AF8E51", "30C81C46A35CE411E5FBC1191A0A52EF", "F69F2445DF4F9B17AD2B417BE66C3710",
        "6BC1BEE22E409F96E93D7E117393172A", "AE2D8A571E03AC9C9EB76FAC45AF8E51", "30C81C46A35CE411E5FBC1191A0A52EF", "F69F2445DF4F9B17AD2B417BE66C3710"
    ];
    
    var iv = [
        "000102030405060708090A0B0C0D0E0F", "7649ABAC8119B246CEE98E9B12E9197D", "5086CB9B507219EE95DB113A917678B2", "73BED6B8E3C1743B7116E69E22229516",
        "000102030405060708090A0B0C0D0E0F", "4F021DB243BC633D7178183A9FA071E8", "B4D9ADA9AD7DEDF4E5E738763F69145A", "571B242012FB7AE07FA9BAAC3DF102E0",
        "000102030405060708090A0B0C0D0E0F", "F58C4C04D6E5F1BA779EABFB5F7BFBD6", "9CFC4E967EDB808D679F777BC6702C7D", "39F23369A9D9BACFA530E26304231461"
    ];

    var cbc_txt = [
        "6BC0BCE12A45999182FDC2F059D68EBB", "D86421FB9F1A1EDA46D34E57DAB5908B", "604ED7DDF32EFDFF85B516C4E924AF10", "8521F2FD3C8EEF2C280AB386DAE2D83C",
        "6BC0BCE12A45999182FDC2F059D68EBB", "E12F97E55DBFCFA17F98F849181041F0", "8411B1EF0E2109E561EA70F6142B5B0A", "A1840065CDB4E1F70CAF411E2BD8D6E7",
        "6BC0BCE12A45999182FDC2F059D68EBB", "5BA1C653C8E65D26C516A9FF8D49D377", "AC3452D0DD87649C49CF93C9C78D3673", "CF6D172C769621D86246565790FA16C8"
    ];

    var cfb_txt = [
        "6BC0BCE12A45999182FDC2F059D68EBB", "D86421FB9F1A1EDA46D34E57DAB5908B", "604ED7DDF32EFDFF85B516C4E924AF10", "8521F2FD3C8EEF2C280AB386DAE2D83C",
        "6BC0BCE12A45999182FDC2F059D68EBB", "E12F97E55DBFCFA17F98F849181041F0", "8411B1EF0E2109E561EA70F6142B5B0A", "A1840065CDB4E1F70CAF411E2BD8D6E7",
        "6BC0BCE12A45999182FDC2F059D68EBB", "5BA1C653C8E65D26C516A9FF8D49D377", "AC3452D0DD87649C49CF93C9C78D3673", "CF6D172C769621D86246565790FA16C8"
    ];
    
    var ctr_txt = [
        "6BC0BCE12A459991E93C7C1277961122", "D86421FB9F1A1EDAE8FEC400C4B63C16", "604ED7DDF32EFDFFB57D0A824A784B00", "8521F2FD3C8EEF2CDE9597C305AD432C",
        "6BC0BCE12A459991E93C7C1277961122", "E12F97E55DBFCFA1D1B5721E0613ED6F", "8411B1EF0E2109E551226CB0B777BF1A", "A1840065CDB4E1F7FA30655BF4974DF1",
        "6BC0BCE12A459991E93C7C1277961122", "5BA1C653C8E65D266B3B23A8934A7FEA", "AC3452D0DD87649C79078F8F64D1D261", "CF6D172C769621D894D972124FB58DC0"
    ];
    
    var ecb_txt = [
        "6BC1BEE22E409F96E93D7E117393172A", "AE2D8A571E03AC9C9EB76FAC45AF8E51", "30C81C46A35CE411E5FBC1191A0A52EF", "F69F2445DF4F9B17AD2B417BE66C3710",
        "6BC1BEE22E409F96E93D7E117393172A", "AE2D8A571E03AC9C9EB76FAC45AF8E51", "30C81C46A35CE411E5FBC1191A0A52EF", "F69F2445DF4F9B17AD2B417BE66C3710",
        "6BC1BEE22E409F96E93D7E117393172A", "AE2D8A571E03AC9C9EB76FAC45AF8E51", "30C81C46A35CE411E5FBC1191A0A52EF", "F69F2445DF4F9B17AD2B417BE66C3710"
    ];
    
    var ofb_txt = [
        "6BC0BCE12A459991E93C7C127796112D", "D86421FB9F1A1EDAE8FEC400C4B63C17", "604ED7DDF32EFDFFB57D0A824A784B01", "8521F2FD3C8EEF2CDE9597C305AD432B",
        "6BC0BCE12A459991E93C7C127796112D", "E12F97E55DBFCFA1D1B5721E0613ED6C", "8411B1EF0E2109E551226CB0B777BF1B", "A1840065CDB4E1F7FA30655BF4974DF0",
        "6BC0BCE12A459991E93C7C127796112D", "5BA1C653C8E65D266B3B23A8934A7FEB", "AC3452D0DD87649C79078F8F64D1D262", "CF6D172C769621D894D972124FB58DDF"
    ];
        
    var pcbc_txt = [
        "6BC0BCE12A459991E93C7C127796112D", "D86421FB9F1A1EDAE8FEC400C4B63C17", "604ED7DDF32EFDFFB57D0A824A784B01", "8521F2FD3C8EEF2CDE9597C305AD432B",
        "6BC0BCE12A459991E93C7C127796112D", "E12F97E55DBFCFA1D1B5721E0613ED6C", "8411B1EF0E2109E551226CB0B777BF1B", "A1840065CDB4E1F7FA30655BF4974DF0",
        "6BC0BCE12A459991E93C7C127796112D", "5BA1C653C8E65D266B3B23A8934A7FEB", "AC3452D0DD87649C79078F8F64D1D262", "CF6D172C769621D894D972124FB58DDF"
    ];

    static inline var BLOCK_SIZE : Int = 8;

    public function new()
    {
        test_encrypt();
        test_decrypt();
    }

    private function  encryptBlock( src:Bytes, srcIndex:Int, dst:Bytes, dstIndex:Int):Void
    {
    }

    private function  decryptBlock( src:Bytes, srcIndex:Int, dst:Bytes, dstIndex:Int):Void
    {
    }

    private function checkmode(mode:String,data:Bytes,type:Mode):Void
    {
        if ( mode !=  data.toHex().toUpperCase() ) throw "Wrong mode "+type+" . Got "+data.toHex().toUpperCase()+" expected "+mode;
           
    }

    private function test_encrypt():Void
    {
        var src:Bytes;
        var vector:Bytes;
        for(i in 0...plainText.length) 
        {
            src = Bytes.ofHex(plainText[i]);
            vector = Bytes.ofHex(iv[i]);
            CBC.encrypt(src,vector,BLOCK_SIZE,encryptBlock);
            checkmode(cbc_txt[i],src,Mode.CBC);
            src = Bytes.ofHex(plainText[i]);
            CFB.encrypt(src,vector,BLOCK_SIZE,encryptBlock);
            checkmode(cfb_txt[i],src,Mode.CFB);
            src = Bytes.ofHex(plainText[i]);
            CTR.encrypt(src,vector,BLOCK_SIZE,encryptBlock);
            checkmode(ctr_txt[i],src,Mode.CTR);
            src = Bytes.ofHex(plainText[i]);
            ECB.encrypt(src,BLOCK_SIZE,encryptBlock);
            checkmode(ecb_txt[i],src,Mode.ECB);
            src = Bytes.ofHex(plainText[i]);
            OFB.encrypt(src,vector,BLOCK_SIZE,encryptBlock);
            checkmode(ofb_txt[i],src,Mode.OFB);
            src = Bytes.ofHex(plainText[i]);
            PCBC.encrypt(src,vector,BLOCK_SIZE,encryptBlock);
            checkmode(pcbc_txt[i],src,Mode.PCBC);
        }
        
    }

    private function test_decrypt():Void
    {
       var src:Bytes;
        var vector:Bytes;
        for(i in 0...plainText.length) 
        {
            src = Bytes.ofHex(cbc_txt[i]);
            vector = Bytes.ofHex(iv[i]);
            CBC.decrypt(src,vector,BLOCK_SIZE,decryptBlock);
            checkmode(plainText[i],src,Mode.CBC);
            src = Bytes.ofHex(cfb_txt[i]);
            CFB.decrypt(src,vector,BLOCK_SIZE,decryptBlock);
            checkmode(plainText[i],src,Mode.CFB);
            src = Bytes.ofHex(ctr_txt[i]);
            CTR.decrypt(src,vector,BLOCK_SIZE,decryptBlock);
            checkmode(plainText[i],src,Mode.CTR);
            src = Bytes.ofHex(ecb_txt[i]);
            ECB.decrypt(src,BLOCK_SIZE,decryptBlock);
            checkmode(plainText[i],src,Mode.ECB);
            src = Bytes.ofHex(ofb_txt[i]);
            OFB.decrypt(src,vector,BLOCK_SIZE,decryptBlock);
            checkmode(plainText[i],src,Mode.OFB);
            src = Bytes.ofHex(pcbc_txt[i]);
            PCBC.decrypt(src,vector,BLOCK_SIZE,decryptBlock);
            checkmode(plainText[i],src,Mode.PCBC);
        }
    }
}
