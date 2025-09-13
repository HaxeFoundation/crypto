package haxe.crypto;

import haxe.ds.Vector;
import haxe.io.Bytes;
import haxe.crypto.mode.*;
import haxe.crypto.padding.*;

class Aes {
	private static var SBOX:Vector<Int>;
	private static var RSBOX:Vector<Int>;
	private static var SUB_BYTES_MIX_COLUMN_0:Vector<Int>;
	private static var SUB_BYTES_MIX_COLUMN_1:Vector<Int>;
	private static var SUB_BYTES_MIX_COLUMN_2:Vector<Int>;
	private static var SUB_BYTES_MIX_COLUMN_3:Vector<Int>;
	private static var RSUB_BYTES_MIX_COLUMN_0:Vector<Int>;
	private static var RSUB_BYTES_MIX_COLUMN_1:Vector<Int>;
	private static var RSUB_BYTES_MIX_COLUMN_2:Vector<Int>;
	private static var RSUB_BYTES_MIX_COLUMN_3:Vector<Int>;
	private static var RCON:Vector<Int>;

	private static inline var BLOCK_SIZE:Int = 16;

	private var Nk:Int;
	private var Nr:Int;

	private var roundKey:Vector<Int>;
	private var rRoundKey:Vector<Int>;

	private var keyRows:Int;
	private var state:Vector<Int>;

	public var key:Bytes;

	public var iv(default, set):Bytes;

	function set_iv(vector) {
		iv = vector;
		return iv;
	}

	public function new(?key:Bytes, ?iv:Bytes) {
		initTable();
		if (key != null)
			init(key, iv);
	}

	public function init(key:Bytes, ?iv:Bytes):Void {
		this.key = key;
		Nk = key.length >> 2;
		Nr = Nk + 6;
		keyRows = (Nr + 1) * 4;
		state = new Vector<Int>(Nk);
		this.iv = iv;
		keyExpansion(key);
	}

	private static function initTable():Void {
		SBOX = new Vector<Int>(256);
		RSBOX = new Vector<Int>(256);
		SUB_BYTES_MIX_COLUMN_0 = new Vector<Int>(256);
		SUB_BYTES_MIX_COLUMN_1 = new Vector<Int>(256);
		SUB_BYTES_MIX_COLUMN_2 = new Vector<Int>(256);
		SUB_BYTES_MIX_COLUMN_3 = new Vector<Int>(256);
		RSUB_BYTES_MIX_COLUMN_0 = new Vector<Int>(256);
		RSUB_BYTES_MIX_COLUMN_1 = new Vector<Int>(256);
		RSUB_BYTES_MIX_COLUMN_2 = new Vector<Int>(256);
		RSUB_BYTES_MIX_COLUMN_3 = new Vector<Int>(256);
		RCON = new Vector<Int>(11);
		var d:Vector<Int> = new Vector<Int>(256);
		for (i in 0...256) {
			if (i < 128) {
				d[i] = i << 1;
			} else {
				d[i] = (i << 1) ^ 0x11b;
			}
		}
		var x:Int = 0;
		var xi:Int = 0;
		for (i in 0...256) {
			var sx:Int32 = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
			sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
			SBOX[x] = sx;
			RSBOX[sx] = x;

			var x2:Int = d[x];
			var x4:Int = d[x2];
			var x8:Int = d[x4];

			var t:Int32 = (d[sx] * 0x101) ^ (sx * 0x1010100);
			SUB_BYTES_MIX_COLUMN_0[x] = (t << 24) | (t >>> 8);
			SUB_BYTES_MIX_COLUMN_1[x] = (t << 16) | (t >>> 16);
			SUB_BYTES_MIX_COLUMN_2[x] = (t << 8) | (t >>> 24);
			SUB_BYTES_MIX_COLUMN_3[x] = t;

			t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
			RSUB_BYTES_MIX_COLUMN_0[sx] = (t << 24) | (t >>> 8);
			RSUB_BYTES_MIX_COLUMN_1[sx] = (t << 16) | (t >>> 16);
			RSUB_BYTES_MIX_COLUMN_2[sx] = (t << 8) | (t >>> 24);
			RSUB_BYTES_MIX_COLUMN_3[sx] = t;
			if (x == 0) {
				x = xi = 1;
			} else {
				x = x2 ^ d[d[d[x8 ^ x2]]];
				xi ^= d[d[xi]];
			}
		}
		RCON[0] = 0x0;
		RCON[1] = 0x1;
		RCON[2] = 0x2;
		RCON[3] = 0x4;
		RCON[4] = 0x8;
		RCON[5] = 0x10;
		RCON[6] = 0x20;
		RCON[7] = 0x40;
		RCON[8] = 0x80;
		RCON[9] = 0x1b;
		RCON[10] = 0x36;
	}

	private function keyExpansion(key:Bytes):Void {
		roundKey = new Vector<Int>(keyRows);
		for (ksRow in 0...keyRows) {
			if (ksRow < Nk) {
				roundKey[ksRow] = bytesToInt32(key, ksRow << 2);
			} else {
				var t:Int32 = roundKey[ksRow - 1];
				if ((ksRow % Nk) == 0) {
					t = (t << 8) | (t >>> 24);
					t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
					t ^= RCON[Math.floor(ksRow / Nk) | 0] << 24;
				} else if (Nk > 6 && ksRow % Nk == 4) {
					t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
				}
				roundKey[ksRow] = roundKey[ksRow - Nk] ^ t;
			}
		}
		rRoundKey = new Vector<Int>(keyRows);
		var keyRow:Int, t:Int;
		for (i in 0...keyRows) {
			keyRow = keyRows - i;

			if ((i % 4) != 0) {
				t = roundKey[keyRow];
			} else {
				t = roundKey[keyRow - 4];
			}

			if (i < 4 || keyRow <= 4) {
				rRoundKey[i] = t;
			} else {
				rRoundKey[i] = RSUB_BYTES_MIX_COLUMN_0[SBOX[t >>> 24]] ^ RSUB_BYTES_MIX_COLUMN_1[SBOX[(t >>> 16) & 0xff]] ^ RSUB_BYTES_MIX_COLUMN_2[SBOX[(t >>> 8) & 0xff]] ^ RSUB_BYTES_MIX_COLUMN_3[SBOX[t & 0xff]];
			}
		}
	}

	public function getBlockSize():Int {
		return BLOCK_SIZE;
	}

	public function encrypt(cipherMode:Mode, data:Bytes, ?padding:Padding = Padding.NoPadding, ?aad:Bytes, ?tagLen:Int = 16, ?aadCollection:Array<Bytes>):Bytes {
		var out:Bytes;

		switch (padding) {
			// CBC, ECB  and PCBC requires padding
			case Padding.NoPadding:
				out = NoPadding.pad(data, BLOCK_SIZE);
			case Padding.PKCS7:
				out = PKCS7.pad(data, BLOCK_SIZE);
			case Padding.BitPadding:
				out = BitPadding.pad(data, BLOCK_SIZE);
			case Padding.AnsiX923:
				out = AnsiX923.pad(data, BLOCK_SIZE);
			case Padding.ISO10126:
				out = ISO10126.pad(data, BLOCK_SIZE);
			case Padding.NullPadding:
				out = NullPadding.pad(data, BLOCK_SIZE);
			case Padding.SpacePadding:
				out = SpacePadding.pad(data, BLOCK_SIZE);
			case Padding.TBC:
				out = TBC.pad(data, BLOCK_SIZE);
		}

		switch (cipherMode) {
			case Mode.CBC:
				CBC.encrypt(out, iv, BLOCK_SIZE, encryptBlock);
			case Mode.ECB:
				ECB.encrypt(out, BLOCK_SIZE, encryptBlock);
			case Mode.PCBC:
				PCBC.encrypt(out, iv, BLOCK_SIZE, encryptBlock);
			case Mode.CTR:
				CTR.encrypt(out, iv, BLOCK_SIZE, encryptBlock);
			case Mode.CFB:
				CFB.encrypt(out, iv, BLOCK_SIZE, encryptBlock);
			case Mode.OFB:
				OFB.encrypt(out, iv, BLOCK_SIZE, encryptBlock);
			case Mode.CCM:
				return CCM.encrypt(out, iv, aad, tagLen, BLOCK_SIZE, encryptBlock);
			case Mode.GCM:
				return GCM.encrypt(out, iv, aad, tagLen, BLOCK_SIZE, encryptBlock);
			case Mode.SIV:
				return SIV.encrypt(key, out, iv, aadCollection, encryptBlock, init);
			case Mode.GCMSIV:
				return GCMSIV.encrypt(key, iv, out, aad, encryptBlock, init);
			case Mode.EAX:
				return EAX.encrypt(out, key, iv, encryptBlock, aadCollection);
		}

		return out;
	}

	public function decrypt(cipherMode:Mode, data:Bytes, ?padding:Padding = Padding.NoPadding,?aad:Bytes,?tagLen:Int = 16,?aadCollection:Array<Bytes>):Bytes {
		var out:Bytes = data.sub(0, data.length);

		switch (cipherMode) {
			case Mode.CBC:
				CBC.decrypt(out, iv, BLOCK_SIZE, decryptBlock);
			case Mode.ECB:
				ECB.decrypt(out, BLOCK_SIZE, decryptBlock);
			case Mode.PCBC:
				PCBC.decrypt(out, iv, BLOCK_SIZE, decryptBlock);
			case Mode.CTR:
				CTR.decrypt(out, iv, BLOCK_SIZE, encryptBlock);
			case Mode.CFB:
				CFB.decrypt(out, iv, BLOCK_SIZE, encryptBlock);
			case Mode.OFB:
				OFB.decrypt(out, iv, BLOCK_SIZE, encryptBlock);
			case Mode.CCM:
				return CCM.decrypt(out, iv, aad, tagLen, BLOCK_SIZE, encryptBlock);
			case Mode.GCM:
				return GCM.decrypt(out,iv,aad,tagLen,BLOCK_SIZE, encryptBlock);
			case Mode.SIV:
				return SIV.decrypt(key, out, iv, aadCollection, encryptBlock, init);
			case Mode.GCMSIV:
				return GCMSIV.decrypt(key, iv, out, aad, encryptBlock, init);
			case Mode.EAX:
				return EAX.decrypt(out, key, iv, encryptBlock, aadCollection);
		}

		switch (padding) {
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

	public function encryptBlock(src:Bytes, srcIndex:Int, dst:Bytes, dstIndex:Int):Void {
		for (i in 0...4) {
			state[i] = bytesToInt32(src, srcIndex + (i << 2));
		}
		generateBlock(roundKey, SUB_BYTES_MIX_COLUMN_0, SUB_BYTES_MIX_COLUMN_1, SUB_BYTES_MIX_COLUMN_2, SUB_BYTES_MIX_COLUMN_3, SBOX);
		for (i in 0...4) {
			int32ToBytes(state[i], dst, dstIndex + (i << 2));
		}
	}

	public function decryptBlock(src:Bytes, srcIndex:Int, dst:Bytes, dstIndex:Int = 0):Void {
		for (i in 0...4) {
			state[i] = bytesToInt32(src, srcIndex + (i << 2));
		}
		var t:Int = state[1];
		state[1] = state[3];
		state[3] = t;
		generateBlock(rRoundKey, RSUB_BYTES_MIX_COLUMN_0, RSUB_BYTES_MIX_COLUMN_1, RSUB_BYTES_MIX_COLUMN_2, RSUB_BYTES_MIX_COLUMN_3, RSBOX);
		t = state[1];
		state[1] = state[3];
		state[3] = t;
		for (i in 0...4) {
			int32ToBytes(state[i], dst, dstIndex + (i << 2));
		}
	}

	private function generateBlock(keySchedule:Vector<Int>, SUB_MIX_0:Vector<Int>, SUB_MIX_1:Vector<Int>, SUB_MIX_2:Vector<Int>, SUB_MIX_3:Vector<Int>,
			SBOX:Vector<Int>):Void {
		var state0:Int = state[0] ^ keySchedule[0];
		var state1:Int = state[1] ^ keySchedule[1];
		var state2:Int = state[2] ^ keySchedule[2];
		var state3:Int = state[3] ^ keySchedule[3];

		var ksRow:Int = 4;
		var tmp0:Int;
		var tmp1:Int;
		var tmp2:Int;
		var tmp3:Int;

		for (round in 1...Nr) {
			tmp0 = SUB_MIX_0[state0 >>> 24] ^ SUB_MIX_1[(state1 >>> 16) & 0xff] ^ SUB_MIX_2[(state2 >>> 8) & 0xff] ^ SUB_MIX_3[state3 & 0xff] ^ keySchedule[ksRow++];
			tmp1 = SUB_MIX_0[state1 >>> 24] ^ SUB_MIX_1[(state2 >>> 16) & 0xff] ^ SUB_MIX_2[(state3 >>> 8) & 0xff] ^ SUB_MIX_3[state0 & 0xff] ^ keySchedule[ksRow++];
			tmp2 = SUB_MIX_0[state2 >>> 24] ^ SUB_MIX_1[(state3 >>> 16) & 0xff] ^ SUB_MIX_2[(state0 >>> 8) & 0xff] ^ SUB_MIX_3[state1 & 0xff] ^ keySchedule[ksRow++];
			tmp3 = SUB_MIX_0[state3 >>> 24] ^ SUB_MIX_1[(state0 >>> 16) & 0xff] ^ SUB_MIX_2[(state1 >>> 8) & 0xff] ^ SUB_MIX_3[state2 & 0xff] ^ keySchedule[ksRow++];

			state0 = tmp0;
			state1 = tmp1;
			state2 = tmp2;
			state3 = tmp3;
		}

		tmp0 = ((SBOX[state0 >>> 24] << 24) | (SBOX[(state1 >>> 16) & 0xff] << 16) | (SBOX[(state2 >>> 8) & 0xff] << 8) | SBOX[state3 & 0xff]) ^ keySchedule[ksRow++];
		tmp1 = ((SBOX[state1 >>> 24] << 24) | (SBOX[(state2 >>> 16) & 0xff] << 16) | (SBOX[(state3 >>> 8) & 0xff] << 8) | SBOX[state0 & 0xff]) ^ keySchedule[ksRow++];
		tmp2 = ((SBOX[state2 >>> 24] << 24) | (SBOX[(state3 >>> 16) & 0xff] << 16) | (SBOX[(state0 >>> 8) & 0xff] << 8) | SBOX[state1 & 0xff]) ^ keySchedule[ksRow++];
		tmp3 = ((SBOX[state3 >>> 24] << 24) | (SBOX[(state0 >>> 16) & 0xff] << 16) | (SBOX[(state1 >>> 8) & 0xff] << 8) | SBOX[state2 & 0xff]) ^ keySchedule[ksRow++];

		state[0] = tmp0;
		state[1] = tmp1;
		state[2] = tmp2;
		state[3] = tmp3;
	}

	private function bytesToInt32(bs:Bytes, off:Int):Int32 {
		var n:Int32 = (bs.get(off) & 0xff) << 24;
		n |= (bs.get(++off) & 0xff) << 16;
		n |= (bs.get(++off) & 0xff) << 8;
		n |= bs.get(++off) & 0xff;
		return n;
	}

	private function int32ToBytes(n:Int32, bs:Bytes, off:Int):Void {
		bs.set(off, (n >> 24));
		bs.set(++off, (n >> 16));
		bs.set(++off, (n >> 8));
		bs.set(++off, (n));
	}
}
