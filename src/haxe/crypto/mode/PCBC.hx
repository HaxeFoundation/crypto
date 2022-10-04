package haxe.crypto.mode;

import haxe.io.Bytes;

class PCBC
{
    public static function encrypt( src : Bytes, iv : Bytes, blockSize : Int, encryptBlock : Bytes->Int->Bytes->Int->Void) : Void
    {
        var vector = iv.sub(0,iv.length);
        var i : Int = 0;
        var len : Int = src.length;
        var plainText:Bytes = Bytes.alloc(blockSize);
        while (i < len)
        {
            for (j in 0...blockSize)
            {
                plainText.set(j, src.get(i + j));
                src.set(i + j, src.get(i + j) ^ vector.get(j) );
            }
            encryptBlock(src, i, src , i);
            for (j in 0...blockSize)
            {
                vector.set(j, src.get(i + j) ^ plainText.get(j));
            }
            i += blockSize;
        }
    }

    public static function decrypt( src : Bytes, iv : Bytes, blockSize : Int, decryptBlock : Bytes->Int->Bytes->Int->Void) : Void
    {
        var vector = iv.sub(0,iv.length);
        var i : Int = 0;
        var len : Int = src.length;
        var cipherText:Bytes = Bytes.alloc(blockSize);
        while (i < len)
        {
            for (j in 0...blockSize) {
                cipherText.set(j, src.get(i + j));
            }
            decryptBlock(src, i, src, i);
            for (j in 0 ... blockSize) {
                src.set(i + j, src.get(i + j) ^ vector.get(j));
                vector.set(j, src.get(i + j) ^ cipherText.get(j));
            }
            i += blockSize;
        }
    }
}
