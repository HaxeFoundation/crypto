package haxe.crypto;

import haxe.ds.Vector;
import haxe.io.Bytes;

class XSalsa20 extends Salsa20
{
    private var nonce:Bytes;

    public override function init(key:Bytes,nonce:Bytes,?counter:Int64):Void
	{
        if ( nonce == null || nonce.length != 24 ) 
			throw "Nonce must be exactly 24 bytes";
		if ( key == null ) 
			throw "Key must be 32 bytes";
		if ( key.length != 32 )
			throw "Wrong key size. Exptected 32 bytes key";
		
		setConstant(key);
		setNonce(nonce);
		setKey(key);
		reset();
		if (counter != null ) setCounter(counter);
	}

    public override function setNonce(nonce:Bytes):Void
	{
        super.setNonce(nonce);
        this.nonce = nonce;
    }

    public override function setKey(key:Bytes):Void
    {
        if ( key.length != 32 )
			throw "Wrong key size. Exptected 32 bytes key";
        
        super.setKey(key);

        for(i in 0...2) {
            state[i+8] = bytesToInt32(nonce,i*4+8);
		}
        
        var xsalsa20Buffer:Vector<Int> = new Vector<Int>(16);
        generateBlock(state,xsalsa20Buffer);

        state[1] = xsalsa20Buffer[0] - state[0];
        state[2] = xsalsa20Buffer[5] - state[5];
        state[3] = xsalsa20Buffer[10] - state[10];
        state[4] = xsalsa20Buffer[15] - state[15];
        state[11] = xsalsa20Buffer[6] - state[6];
        state[12] = xsalsa20Buffer[7] - state[7];
        state[13] = xsalsa20Buffer[8] - state[8];
        state[14] = xsalsa20Buffer[9] - state[9];

        for(i in 0...2) {
            state[i+6] = bytesToInt32(nonce,i*4+16);
		}
    }
}