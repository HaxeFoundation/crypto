package haxe.crypto;

import haxe.io.Bytes;
import haxe.io.BytesBuffer;

class Ripemd160
{
    public static inline var DIGEST_SIZE : Int = 20; //160 bits
    public static inline var BLOCK_SIZE : Int = 64;

    private var KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
	private var KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];

    private var RL = [
		 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
		 7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
		 3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
		 1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
		 4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13];
	
	private var RR = [
		 5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
		 6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
		15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
		 8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
		12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11];
	
	private var SL = [
		11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
		 7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
		11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
		11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
		 9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6];
	
	private var SR = [
		 8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
		 9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
		 9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
		15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
		 8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11];

    private var state : Array<Int>;
    private var bytesBuffer : BytesBuffer;

    public static function encode( s : String ) : String
    {
        var b = Bytes.ofString(s);
        var ripemd160 = new Ripemd160();
        ripemd160.bytesBuffer.addBytes(b,0,b.length);
        var data = ripemd160.finish();
        return data.toHex();
    }

    public static function make( b : Bytes ) : Bytes 
    {
        var ripemd160 = new Ripemd160();
        ripemd160.bytesBuffer.addBytes(b,0,b.length);
        var data = ripemd160.finish();
        return data;
    }

    public function finish() : Bytes
	{
        var b = bytesBuffer.getBytes();
        var len = b.length;
        var offset  = Math.floor(len/BLOCK_SIZE);
        for(i in 0...offset) {
            process(b,i*BLOCK_SIZE);
        }
        offset *= BLOCK_SIZE;
        var block = Bytes.alloc(BLOCK_SIZE);
        block.fill(0,block.length,0);
        block.blit(0,b,offset,len-offset);
        offset = len % block.length;
        block.set(offset, 0x80);
        if ( (offset+8) >= BLOCK_SIZE) {
            process(block,0);
            block.fill(0,block.length,0);
        }
        
        len = len << 3;
        for(i in 0...8) {
			if ( i > 3 ) {
                block.set(block.length - 8 +i, 0 );
            } else {
				block.set(block.length - 8 +i, len >>> (i * 8) );
			}
		}
        offset = 0;
        while ( offset < block.length)
        {
            process(block,offset);
            offset += 64;
        }
        
        var data = Bytes.alloc(20);
        for(i in 0...5) {
            int32ToBytes(state[i],data,i*4);
        }

        bytesBuffer = new BytesBuffer();
        clear();

        return data;
    }

    public function addByte(byte : Int) : Void
	{
		bytesBuffer.addByte(byte);
	}

	public function addBytes(bytes : Bytes, pos:Int, len:Int) : Void
	{
		bytesBuffer.addBytes(bytes, pos, len);
	}


    public function clear() : Void
	{
        state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    }

    public function new()
    {
        bytesBuffer = new BytesBuffer();
        clear();
    }

    public function process(src:Bytes, offset:Int) : Void
	{
        var data : Array<Int> = new Array();
        for(i in 0...16) {
            data.push(bytesToInt32(src,offset + i*4));
        }
        var al = state[0], ar = state[0];
        var bl = state[1], br = state[1];
        var cl = state[2], cr = state[2];
        var dl = state[3], dr = state[3];
        var el = state[4], er = state[4];
        for(i in 0...80) 
        {
            var tlr = rol32(al + fn(i, bl, cl, dl) + data[RL[i]] + KL[i >>> 4], SL[i]) + el;
			al = el;
			el = dl;
			dl = rol32(cl, 10);
			cl = bl;
			bl = tlr;

			tlr = rol32(ar + fn(79 - i, br, cr, dr) + data[RR[i]] + KR[i >>> 4], SR[i]) + er;
			ar = er;
			er = dr;
			dr = rol32(cr, 10);
			cr = br;
			br = tlr;
        }
        var t = state[1] + cl + dr;
		state[1] = state[2] + dl + er;
		state[2] = state[3] + el + ar;
		state[3] = state[4] + al + br;
		state[4] = state[0] + bl + cr;
		state[0] = t;
    }

    private function fn(i:Int, x:Int, y:Int, z:Int) {
		if (i < 16) return x ^ y ^ z;
		if (i < 32) return (x & y) | (~x & z);
		if (i < 48) return (x | ~y) ^ z;
		if (i < 64) return (x & z) | (y & ~z);
		return x ^ (y | ~z);
	}

    private function rol32(x:Int, n:Int):Int {
        return ( (x << n) | (x >>> (32 - n)) );
    }

    private function int32ToBytes(n:Int, bs:Bytes, off:Int):Void
	{
		bs.set( off , (n ));
		bs.set(++off, (n >>> 8));
		bs.set(++off, (n >>>  16));
		bs.set(++off, (n >>> 24));
	}

    private function bytesToInt32(bs:Bytes, off:Int):Int
	{
		var n:Int = ( bs.get(off) );
		n |= ( bs.get(++off) ) << 8;
		n |= ( bs.get(++off) ) << 16;
		n |= bs.get(++off)   << 24;
		return n;
	}
}