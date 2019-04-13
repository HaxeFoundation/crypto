package haxe.crypto;

import haxe.ds.Vector;
import haxe.io.Bytes;

import haxe.crypto.mode.*;
import haxe.crypto.padding.*;

class TwoFish
{
    static var Q0:Vector<Int>;
    static var Q1:Vector<Int>;

    public static var Q0_ARRAY:Array<Int> = [
       	0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
		0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
		0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
		0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
		0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
		0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
		0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
		0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
		0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
		0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
		0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
		0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
		0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
		0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
		0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
		0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0
    ];

    public static var Q1_ARRAY:Array<Int> = [
       	0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
		0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
		0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
		0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
		0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
		0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
		0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
		0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
		0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
		0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
		0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
		0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
		0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
		0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
		0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
		0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91
    ];

    static inline var MDS_GF_FDBK_2 = 180; // 0x169 / 2
    static inline var MDS_GF_FDBK_4 = 90; // 0x169 / 4;
    static inline var RS_GF_FDBK = 0x14d;

    static inline var SUBKEY_STEP  = 0x02020202;
    static inline var SUBKEY_BUMP = 0x01010101;
    static inline var SUBKEY_ROTL = 9;

    static inline var BLOCK_SIZE : Int = 16;
    static inline var ROUNDS : Int = 16;
    static inline var INPUT_WHITEN : Int = 0;
    static inline var OUTPUT_WHITEN : Int = INPUT_WHITEN + ( BLOCK_SIZE >> 2 );
    static inline var ROUND_SUBKEYS : Int = OUTPUT_WHITEN + ( BLOCK_SIZE >> 2 );
    static inline var COUNT_SUBKEYS : Int = ROUND_SUBKEYS + 2*ROUNDS;

    private var sBoxKeys  : Vector<Int>;
    private var subKeys : Vector<Int>;
    private var keyLength : Int;
    private var mdsMatrix : Vector<Vector<Int>> = Vector.fromArrayCopy([ for(i in 0...4) Vector.fromArrayCopy([ for (i  in 0...256) 0]) ]);
    public var iv(default, set):Bytes;

    function set_iv(vector) {
        iv = vector;
        if (iv == null) 
        {
            iv = Bytes.alloc(BLOCK_SIZE);
            iv.fill(0,BLOCK_SIZE,0x00);
        }
        
        return iv;
    }

    public function new(?key:Bytes, ?iv:Bytes)
    {
        Q0 = Vector.fromArrayCopy(Q0_ARRAY);
        Q1 = Vector.fromArrayCopy(Q1_ARRAY);
        if ( key != null ) init(key,iv);
        calculateMds();
    }

    public function init(key:Bytes, ?iv:Bytes):Void
    {
        this.iv = iv;
        setKey(key);
    }

    public function getBlockSize():Int
    {
        return BLOCK_SIZE;
    }

    private function setKey(key:Bytes):Void
    {
        keyLength = key.length;
        if ( keyLength != 16 && keyLength != 24  && keyLength != 32 ) throw "Key size should be 128, 192 or 256 bits";
        var k64Cnt = keyLength >> 3;
        var k32e : Vector<Int> = new Vector<Int>(k64Cnt);
        var k32o : Vector<Int> = new Vector<Int>(k64Cnt);
        sBoxKeys = new Vector<Int>(k64Cnt);
        for(i in 0...k64Cnt) 
        {
            var m = i*8;
            k32e[i] = bytesToInt32(key,m);
            k32o[i] = bytesToInt32(key,m+4);
            sBoxKeys[k64Cnt-1-i] = rsMDSEncode(k32e[i],k32o[i]);
        }
        
        var cSubKeys = COUNT_SUBKEYS >> 1;
        subKeys = new Vector<Int>(2*cSubKeys + 1);
        for(i in 0...cSubKeys) 
        {
            var step = i * SUBKEY_STEP;
            var a = f32(step, k32e, keyLength);
            var b = f32(step + SUBKEY_BUMP, k32o, keyLength);
            b = rol32(b, 8);
            a += b;
            b += a;
            subKeys[2 * i]   = a;
            subKeys[2 * i + 1] = rol32( b, SUBKEY_ROTL );
        }
    }

    public function encrypt(cipherMode:Mode, data:Bytes, ?padding:Padding=Padding.PKCS7):Bytes
    { 
        var out:Bytes;
        
        switch(padding)  {
            //CBC, ECB  and PCBC requires padding
            case Padding.NoPadding:
                out = NoPadding.pad(data,BLOCK_SIZE); 
            case Padding.PKCS7:
                out = PKCS7.pad(data,BLOCK_SIZE);
            case Padding.BitPadding:
                out = BitPadding.pad(data,BLOCK_SIZE);
            case Padding.AnsiX923:
                out = AnsiX923.pad(data,BLOCK_SIZE);
            case Padding.ISO10126:
                out = ISO10126.pad(data,BLOCK_SIZE);
            case Padding.NullPadding:
                out = NullPadding.pad(data,BLOCK_SIZE);
            case Padding.SpacePadding:
                out = SpacePadding.pad(data,BLOCK_SIZE);
            case Padding.TBC:
                out = TBC.pad(data,BLOCK_SIZE);
        }

        switch (cipherMode) {
            case Mode.CBC:
                CBC.encrypt(out,iv,BLOCK_SIZE,encryptBlock);
            case Mode.ECB:
                ECB.encrypt(out,BLOCK_SIZE,encryptBlock);
            case Mode.PCBC:
                PCBC.encrypt(out,iv,BLOCK_SIZE,encryptBlock);
            case Mode.CTR:
                CTR.encrypt(out,iv,BLOCK_SIZE,encryptBlock);
            case Mode.CFB:
                CFB.encrypt(out,iv,BLOCK_SIZE,encryptBlock);
            case Mode.OFB:
                OFB.encrypt(out,iv,BLOCK_SIZE,encryptBlock);
        }

        return out;
    }

    public function decrypt(cipherMode:Mode, data:Bytes, ?padding:Padding=Padding.PKCS7):Bytes 
    {
        var out:Bytes = data;

        switch (cipherMode) {
            case Mode.CBC:
                CBC.decrypt(out,iv,BLOCK_SIZE,decryptBlock);
            case Mode.ECB:
                ECB.decrypt(out,BLOCK_SIZE,decryptBlock);
            case Mode.PCBC:
                PCBC.decrypt(out,iv,BLOCK_SIZE,decryptBlock);
            case Mode.CTR:
                CTR.decrypt(out,iv,BLOCK_SIZE,encryptBlock);
            case Mode.CFB:
               CFB.decrypt(out,iv,BLOCK_SIZE,encryptBlock);
            case Mode.OFB:
                OFB.decrypt(out,iv,BLOCK_SIZE,encryptBlock);
        }

        switch(padding)  {
            case Padding.NoPadding:
                out = NoPadding.unpad(out);
            case Padding.PKCS7:
                out = PKCS7.unpad(out);
            case Padding.BitPadding:
                out = BitPadding.unpad(out);
            case Padding.AnsiX923:
                out = AnsiX923.unpad(out);
            case Padding.ISO10126:
                out = ISO10126.unpad(out);
            case Padding.NullPadding:
                out = NullPadding.unpad(out);
            case Padding.SpacePadding:
                out = SpacePadding.unpad(out);
            case Padding.TBC:
                out = TBC.unpad(out);
        }

        return out;
    }

    private function encryptBlock( src:Bytes, offset:Int, dst:Bytes, dstOffset:Int):Void
    {
        var x0 = bytesToInt32(src,offset)  ^ subKeys[INPUT_WHITEN];
        var x1 = bytesToInt32(src,offset + 4)  ^ subKeys[INPUT_WHITEN + 1];
        var x2 = bytesToInt32(src,offset + 8)  ^ subKeys[INPUT_WHITEN + 2];
        var x3 = bytesToInt32(src,offset + 12) ^ subKeys[INPUT_WHITEN + 3];

        for(i in 0...ROUNDS)
        {
            var t0 = f32(x0,sBoxKeys,keyLength);
            var t1 = f32(rol32(x1,8),sBoxKeys,keyLength);

            x3 = rol32(x3, 1);
            x2 ^= t0 + t1 +subKeys[ROUND_SUBKEYS + 2 * i];
            x3 ^= t0 + 2 * t1 + subKeys[ROUND_SUBKEYS + 2 * i + 1];
            x2 = ror32(x2, 1);

            if (i < ROUNDS - 1) {
                t0 = x0; x0 = x2; x2 = t0;
                t1 = x1; x1 = x3; x3 = t1;
            }
        }
        
        int32ToBytes(x0 ^ subKeys[OUTPUT_WHITEN ],dst,dstOffset );
        int32ToBytes(x1 ^ subKeys[OUTPUT_WHITEN + 1],dst,dstOffset + 4 );
        int32ToBytes(x2 ^ subKeys[OUTPUT_WHITEN + 2],dst,dstOffset + 8 );
        int32ToBytes(x3 ^ subKeys[OUTPUT_WHITEN + 3],dst,dstOffset + 12 );
    }

    private function decryptBlock( src:Bytes, offset:Int, dst:Bytes, dstOffset:Int):Void
    {
        var x0 = bytesToInt32(src,offset)  ^ subKeys[OUTPUT_WHITEN];
        var x1 = bytesToInt32(src,offset + 4)  ^ subKeys[OUTPUT_WHITEN + 1];
        var x2 = bytesToInt32(src,offset + 8)  ^ subKeys[OUTPUT_WHITEN + 2];
        var x3 = bytesToInt32(src,offset + 12) ^ subKeys[OUTPUT_WHITEN + 3];

        var i = ROUNDS - 1;
        while ( i >= 0 ) {
            var t0 = f32(x0,sBoxKeys, keyLength);
            var t1 = f32(rol32(x1,8), sBoxKeys, keyLength);

            x2 = rol32(x2,1);
            x2 ^= t0 + t1 + subKeys[ROUND_SUBKEYS+2*i];
            x3 ^= t0 + 2*t1 + subKeys[ROUND_SUBKEYS+2*i+1];
            x3 = ror32(x3,1);

            if (i > 0 ) {
                t0 = x0; x0 = x2; x2 = t0;
                t1 = x1; x1 = x3; x3 = t1;
            }
            i--;
        }

        int32ToBytes(x0 ^ subKeys[INPUT_WHITEN ],dst,dstOffset );
        int32ToBytes(x1 ^ subKeys[INPUT_WHITEN + 1],dst,dstOffset + 4 );
        int32ToBytes(x2 ^ subKeys[INPUT_WHITEN + 2],dst,dstOffset + 8 );
        int32ToBytes(x3 ^ subKeys[INPUT_WHITEN + 3],dst,dstOffset + 12 );
    }

    private function calculateMds():Void
    {
        var m1 : Vector<Int> = new Vector<Int>(2);
        var mX : Vector<Int> = new Vector<Int>(2);
        var mY : Vector<Int> = new Vector<Int>(2);

        for (i  in 0...256) 
        {
          m1[0] = Q0[i];
          mX[0] = mulX(m1[0]) & 0xFF;
          mY[0] = mulY(m1[0]) & 0xFF;

          m1[1] = Q1[i];
          mX[1] = mulX(m1[1]) & 0xFF;
          mY[1] = mulY(m1[1]) & 0xFF;

          mdsMatrix[0][i] = m1[1] | mX[1] << 8 | mY[1] << 16 | mY[1] << 24;
          mdsMatrix[1][i] = mY[0] | mY[0] << 8 | mX[0] << 16 | m1[0] << 24;
          mdsMatrix[2][i] = mX[1] | mY[1] << 8 | m1[1] << 16 | mY[1] << 24;
          mdsMatrix[3][i] = mX[0] | m1[0] << 8 | mY[0] << 16 | mX[0] << 24;
        }
    }

    private function mulX(x:Int):Int
    {
        return x ^ lfsr2(x);
    }

    private function mulY(x:Int):Int
    {
        return x ^ lfsr1(x) ^ lfsr2(x);
    }

    private function lfsr1(x:Int):Int
    {

        return ( (x >> 1) ^ ((x & 0x01) > 0 ? MDS_GF_FDBK_2 : 0) );
    }

    private function lfsr2(x:Int):Int
    {
        return ( (x >> 2) ^ ((x & 0x02) > 0 ? MDS_GF_FDBK_2 : 0) 
                          ^ ((x & 0x01) > 0 ? MDS_GF_FDBK_4 : 0));
    }

    public function rsMDSEncode(k0:Int, k1:Int):Int
    {
        var r:Int = k1;
        for(i in 0...2) 
        {
            for(j in 0...4)
            {
                var b:Int = (r >> 24) & 0xff;
                var g2 = ((b << 1) ^ (( (b & 0x80) > 0) ? RS_GF_FDBK : 0)) & 0xff;
                var g3 = (((b >> 1) & 0x7F) ^ (((b & 1) > 0) ? RS_GF_FDBK >> 1 : 0) ^ g2) & 0xff;
                r = ((r << 8) ^ (g3 << 24) ^ (g2 << 16) ^ (g3 << 8) ^ b);
            }
            if ( i == 0) r ^= k0;
        }
        return r;
    }

    public function f32(x:Int, k32:Vector<Int>, keyLenght:Int):Int
    {
        var xb0 = b0(x);
        var xb1 = b1(x);
        var xb2 = b2(x);
        var xb3 = b3(x);
        if (keyLenght >= 32) // 256 bits
        {
            xb0 = Q1[xb0] ^ b0(k32[3]);
            xb1 = Q0[xb1] ^ b1(k32[3]);
            xb2 = Q0[xb2] ^ b2(k32[3]);
            xb3 = Q1[xb3] ^ b3(k32[3]);
        }
        if (keyLenght >= 24) // 192 bits
        {
            xb0 = Q1[xb0] ^ b0(k32[2]);
            xb1 = Q1[xb1] ^ b1(k32[2]);
            xb2 = Q0[xb2] ^ b2(k32[2]);
            xb3 = Q0[xb3] ^ b3(k32[2]);
        }
        if (keyLenght >= 16)  // 128 bits
        {
            x =   mdsMatrix[0][Q0[Q0[xb0] ^ b0(k32[1])] ^ b0(k32[0])]
                ^ mdsMatrix[1][Q0[Q1[xb1] ^ b1(k32[1])] ^ b1(k32[0])]
                ^ mdsMatrix[2][Q1[Q0[xb2] ^ b2(k32[1])] ^ b2(k32[0])]
                ^ mdsMatrix[3][Q1[Q1[xb3] ^ b3(k32[1])] ^ b3(k32[0])];
        }
        return x;
    }

    private function b0(x:Int):Int
    {
        return x & 0xff;
    }

    private function b1(x:Int):Int
    {
        return (x >>> 8) & 0xff;
    }

    private function b2(x:Int):Int
    {
        return (x >>> 16) & 0xff;
    }

    private function b3(x:Int):Int
    {
        return (x >>> 24) & 0xff;
    }

    private function rol32(x:Int, n:Int):Int {
        return ( (x << n) | (x >>> (32 - n)) );
    }

    private function ror32(x:Int, n:Int):Int {
        return ( (x >>> n) | (x << (32 - n)) );
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