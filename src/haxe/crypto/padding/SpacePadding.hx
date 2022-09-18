package haxe.crypto.padding;

import haxe.io.BytesBuffer;
import haxe.io.Bytes;

class SpacePadding
{
    public static  function pad(ciphertext:Bytes, blockSize:Int):Bytes
    {
        var padding:Int = blockSize - ciphertext.length % blockSize;
        var bsize = ciphertext.length+padding;
        var buffer: Bytes =Bytes.alloc(bsize);
        buffer.blit(0,ciphertext,0,ciphertext.length);
        for(i in ciphertext.length...bsize) {
          buffer.set(i,0x20); 
        }
        return buffer;
    }

    public static function unpad(encrypt:Bytes):Bytes
    {
        var padding : Int = 0x20;
        var pos = encrypt.length;
        while ( padding == 0x20 && pos > 0) {
            pos--;
            padding = encrypt.get(pos);
        }
        return encrypt.sub(0,pos+1);
    }
}
