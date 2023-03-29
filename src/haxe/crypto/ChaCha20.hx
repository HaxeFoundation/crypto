package haxe.crypto;

import haxe.ds.Vector;
import haxe.io.Bytes;

class ChaCha20 extends Salsa20
{
	private var nonceLength:Int;

	override public function init(key:Bytes, nonce:Bytes,?counter:Int64):Void
	{
		if (nonce == null)
			throw "A nonce cannot be null";
		
		nonceLength = nonce.length;
		
		if (nonceLength != 8 && nonceLength != 12)
			throw "Nonce must be exactly 8 or 12 bytes";
		if (key == null)
			throw "Key must be 16 or 32 bytes";
		if (key.length != 16 && key.length != 32)
			throw "Wrong key size";
		if ( nonceLength == 12 && key.length != 32)
			throw "Key must be 32 bytes for nonce length of 12 bytes";
			
		
		setConstant(key);
		setNonce(nonce);
		setKey(key);
		reset();
		if (counter != null ) setCounter(counter);
	}
	
	override private function setConstant(key:Bytes):Void
	{
		var sigmaOffset:Int =  (key.length == 16)?0:4;
		state[0] = sigmas[sigmaOffset];
		state[1] = sigmas[sigmaOffset+1];
		state[2] = sigmas[sigmaOffset+2];
		state[3] = sigmas[sigmaOffset+3];
	}

	override public function resetCounter():Void
	{
		counter = 0;
		state[12] = 0;
		if ( nonceLength == 8 ) state[13] = 0;
	}

	override private function updateCounterState():Void
	{
		if ( nonceLength == 12 && ( counter.high > 0 )) throw "Increase of counter past 2^32";
		state[12] = counter.low;
		if ( nonceLength == 8 ) state[13] = counter.high;
	}

	override public function setKey(key:Bytes):Void
	{
		if ( key.length == 16 ) {
			for(i in 0...4) {
				state[i+4] = state[i+8] = bytesToInt32(key,i*4);
			}
		} else {
			for(i in 0...4) {
				state[i+4] = bytesToInt32(key,i*4);
				state[i+8] = bytesToInt32(key,i*4+16);
			}
		}
	}

	override public function setNonce(nonce:Bytes):Void
	{
		if ( nonce.length == 8 ) {
			state[14] = bytesToInt32(nonce, 0);
			state[15] = bytesToInt32(nonce, 4);
		} else {
			state[13] = bytesToInt32(nonce, 0);
			state[14] = bytesToInt32(nonce, 4);
			state[15] = bytesToInt32(nonce, 8);
		}
	}

	override public function generateBlock(input:Vector<Int>, output:Vector<Int>, rounds:Int = 20, offset:Int = 0):Void 
	{
		if ((rounds & 1) != 0) {
			throw "Rounds should be a positive, even number";
		}
		if ((output.length != 16) || input.length != 16) {
			 throw "Invalid buffer size";
		}
		var x0:Int = input[0];
		var x1:Int = input[1];
		var x2:Int = input[2];
		var x3:Int = input[3];
		var x4:Int = input[4];
		var x5:Int = input[5];
		var x6:Int = input[6];
		var x7:Int = input[7];
		var x8:Int = input[8];
		var x9:Int = input[9];
		var x10:Int = input[10];
		var x11:Int = input[11];
		var x12:Int = input[12];
		var x13:Int = input[13];
		var x14:Int = input[14];
		var x15:Int = input[15];

		var h = rounds>>1;
		for(i in 0...h) {
			x0 += x4; x12 = rol32(x12 ^ x0, 16);
			x8 += x12; x4 = rol32(x4 ^ x8, 12);
			x0 += x4; x12 = rol32(x12 ^ x0, 8);
			x8 += x12; x4 = rol32(x4 ^ x8, 7);
			x1 += x5; x13 = rol32(x13 ^ x1, 16);
			x9 += x13; x5 = rol32(x5 ^ x9, 12);
			x1 += x5; x13 = rol32(x13 ^ x1, 8);
			x9 += x13; x5 = rol32(x5 ^ x9, 7);
			x2 += x6; x14 = rol32(x14 ^ x2, 16);
			x10 += x14; x6 = rol32(x6 ^ x10, 12);
			x2 += x6; x14 = rol32(x14 ^ x2, 8);
			x10 += x14; x6 = rol32(x6 ^ x10, 7);
			x3 += x7; x15 = rol32(x15 ^ x3, 16);
			x11 += x15; x7 = rol32(x7 ^ x11, 12);
			x3 += x7; x15 = rol32(x15 ^ x3, 8);
			x11 += x15; x7 = rol32(x7 ^ x11, 7);
			x0 += x5; x15 = rol32(x15 ^ x0, 16);
			x10 += x15; x5 = rol32(x5 ^ x10, 12);
			x0 += x5; x15 = rol32(x15 ^ x0, 8);
			x10 += x15; x5 = rol32(x5 ^ x10, 7);
			x1 += x6; x12 = rol32(x12 ^ x1, 16);
			x11 += x12; x6 = rol32(x6 ^ x11, 12);
			x1 += x6; x12 = rol32(x12 ^ x1, 8);
			x11 += x12; x6 = rol32(x6 ^ x11, 7);
			x2 += x7; x13 = rol32(x13 ^ x2, 16);
			x8 += x13; x7 = rol32(x7 ^ x8, 12);
			x2 += x7; x13 = rol32(x13 ^ x2, 8);
			x8 += x13; x7 = rol32(x7 ^ x8, 7);
			x3 += x4; x14 = rol32(x14 ^ x3, 16);
			x9 += x14; x4 = rol32(x4 ^ x9, 12);
			x3 += x4; x14 = rol32(x14 ^ x3, 8);
			x9 += x14; x4 = rol32(x4 ^ x9, 7);
		}
		output[0] = x0 + input[0];
		output[1] = x1 + input[1];
		output[2] = x2 + input[2];
		output[3] = x3 + input[3];
		output[4] = x4 + input[4];
		output[5] = x5 + input[5];
		output[6] = x6 + input[6];
		output[7] = x7 + input[7];
		output[8] = x8 + input[8];
		output[9] = x9 + input[9];
		output[10] = x10 + input[10];
		output[11] = x11 + input[11];
		output[12] = x12 + input[12];
		output[13] = x13 + input[13];
		output[14] = x14 + input[14];
		output[15] = x15 + input[15];
	}

	private static inline function rol32(x:Int, n:Int):Int {
		return ((x << n) | (x >>> (32 - n)));
	}
}