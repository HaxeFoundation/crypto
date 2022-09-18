package haxe.crypto.padding;

import haxe.io.BytesBuffer;
import haxe.io.Bytes;

class BitPadding 
{
    public static  function pad(ciphertext:Bytes, blockSize:Int):Bytes
    {
      var padding:Int = blockSize - ciphertext.length % blockSize -1;
      var bsize = ciphertext.length+padding+1;
      var buffer: Bytes =Bytes.alloc(bsize);
      buffer.blit(0,ciphertext,0,ciphertext.length);
      buffer.set(ciphertext.length,0x80);
      for(i in (ciphertext.length+1)...bsize) {
        buffer.set(i,0x00); 
      }
      return buffer;
    }

    public static  function unpad(encrypt:Bytes):Bytes
    {
        var padding : Int = 0;
        var pos = encrypt.length-1;
        while ( padding != 0x80 && pos > -1) {
          padding = encrypt.get(pos);
          pos--;
        }
        return encrypt.sub(0,pos+1);
    }
}
