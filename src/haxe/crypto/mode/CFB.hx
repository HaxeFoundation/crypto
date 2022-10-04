package haxe.crypto.mode;

import haxe.io.Bytes;

class CFB
{
    public static function encrypt( src : Bytes, iv : Bytes, blockSize : Int, encryptBlock : Bytes->Int->Bytes->Int->Void) : Void
    {
        var vector = iv.sub(0,iv.length);
        var i : Int = 0;
        var len : Int = src.length;
        while (i < len)
        {
            encryptBlock(vector, 0, vector , 0);
            var block:Int = (i+blockSize)>len?len-i:blockSize;
            for (j in 0...block)
            {
                src.set(i + j, src.get(i + j) ^ vector.get(j) );
                vector.set(j,src.get(i+j));
            }
            i += blockSize;
        }
    }

    public static function decrypt( src : Bytes, iv : Bytes, blockSize : Int, decryptBlock : Bytes->Int->Bytes->Int->Void) : Void
    {
        var vector = iv.sub(0,iv.length);
        var i : Int = 0;
        var len : Int = src.length;
        var vectorResult = Bytes.alloc(iv.length);
        while (i < len)
        {
            decryptBlock(vector, 0, vectorResult , 0);
            var block:Int = (i+blockSize)>len?len-i:blockSize;
            for (j in 0...block)
            {
                vector.set(j, src.get(i + j));
                src.set(i + j, src.get(i + j) ^ vectorResult.get(j) );
            }
            i += blockSize;
        }
    }
}
