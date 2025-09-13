package haxe.crypto.random.csprng;

import haxe.io.Bytes;
import haxe.crypto.Aes;

enum AesVariant {
	AES128;
	AES192;
	AES256;
}

class AesCtrDrbg {
	private static inline var BLOCK_SIZE:Int = 16;
	private static inline var MAX_GENERATE_LENGTH:Int = 65536;
	private static inline var MAX_RESEED_COUNT:Float = 281474976710656;
	private static inline var MAX_NONCE_SIZE:Int = 512;
	private static inline var MAX_SER_SIZE:Int = MAX_NONCE_SIZE * 2 + BLOCK_SIZE * 2;

	private var aes:Aes;
	private var KV:Bytes;
	private var state:Bytes;
	private var reseedCounter:Float;
	private var variant:AesVariant;
	private var keySize:Int;
	private var entSize:Int;
	private var derivation:Bool;

	public function new(variant:AesVariant = AES256, derivation:Bool = true) {
		this.variant = variant;
		this.derivation = derivation;
		keySize = switch (variant) {
			case AES128: 16;
			case AES192: 24;
			case AES256: 32;
		}
		entSize = keySize + BLOCK_SIZE;
		aes = new Aes();
		KV = Bytes.alloc(entSize);
		state = Bytes.alloc(BLOCK_SIZE);
		reseedCounter = 1;
	}

	public function init(entropy:Bytes, ?personalization:Bytes):Bool {
		KV.fill(0, entSize, 0);
		rekey(KV.sub(0, keySize), KV.sub(keySize, BLOCK_SIZE));
		var entropyInput = derivation ? derive(entropy, personalization) : prepareNonDerivationInput(entropy, personalization);
		update(entropyInput);
		reseedCounter = 1;
		return true;
	}

	public function reseed(entropy:Bytes, ?additionalData:Bytes):Bool {
		var entropyInput = derivation ? derive(entropy, additionalData) : prepareNonDerivationInput(entropy, additionalData);
		update(entropyInput);
		reseedCounter = 1;
		return true;
	}

	public function generate(outputLength:Int, ?additionalData:Bytes):Bytes {
		if (outputLength > MAX_GENERATE_LENGTH || reseedCounter >= MAX_RESEED_COUNT) {
			return null;
		}
		var finalAdd:Bytes = additionalData;
		if (additionalData != null && additionalData.length > 0) {
			if (derivation) {
				finalAdd = derive(additionalData, null);
				update(finalAdd);
			} else {
				update(additionalData);
			}
		}
		var output = Bytes.alloc(outputLength);
		var pos = 0;
		var remaining = outputLength;
		while (remaining > 0) {
			var blockOutput = Bytes.alloc(BLOCK_SIZE);
			encrypt(blockOutput);
			var toCopy = remaining < BLOCK_SIZE ? remaining : BLOCK_SIZE;
			output.blit(pos, blockOutput, 0, toCopy);
			pos += toCopy;
			remaining -= toCopy;
		}
		update(finalAdd);
		reseedCounter++;
		return output;
	}

	public function clear():Void {
		if (KV != null)
			KV.fill(0, KV.length, 0);
		if (state != null)
			state.fill(0, state.length, 0);
		reseedCounter = 0;
	}

	private function prepareNonDerivationInput(entropy:Bytes, ?additional:Bytes):Bytes {
		var input = Bytes.alloc(entSize);
		var entropyLen = entropy.length < entSize ? entropy.length : entSize;
		if (entropyLen > 0) {
			input.blit(0, entropy, 0, entropyLen);
		}
		if (additional != null) {
			var addLen = additional.length < entSize ? additional.length : entSize;
			for (i in 0...addLen) {
				input.set(i, input.get(i) ^ additional.get(i));
			}
		}
		return input;
	}

	private function rekey(key:Bytes, counter:Bytes):Void {
		aes.init(key);
		state.blit(0, counter, 0, BLOCK_SIZE);
	}

	private function encrypt(out:Bytes):Void {
		incrementBE(state);
		aes.encryptBlock(state, 0, out, 0);
	}

	private function update(?seed:Bytes):Void {
		var seedLen = seed != null ? (entSize < seed.length ? entSize : seed.length) : 0;
		var i = 0;
		while (i < entSize) {
			var blockOutput = Bytes.alloc(BLOCK_SIZE);
			encrypt(blockOutput);
			var toCopy = BLOCK_SIZE < (entSize - i) ? BLOCK_SIZE : (entSize - i);
			KV.blit(i, blockOutput, 0, toCopy);
			i += BLOCK_SIZE;
		}
		if (seed != null) {
			for (i in 0...seedLen) {
				KV.set(i, KV.get(i) ^ seed.get(i));
			}
		}
		rekey(KV.sub(0, keySize), KV.sub(keySize, BLOCK_SIZE));
	}

	private function incrementBE(bytes:Bytes):Void {
		var carry = 1;
		var i = bytes.length;
		while (i > 0 && carry > 0) {
			i--;
			var val = bytes.get(i) + carry;
			bytes.set(i, val & 0xFF);
			carry = val >> 8;
		}
	}

	private function derive(nonce:Bytes, ?pers:Bytes):Bytes {
		var nonceLen = nonce != null ? (nonce.length > MAX_NONCE_SIZE ? MAX_NONCE_SIZE : nonce.length) : 0;
		var persLen = pers != null ? (pers.length > MAX_NONCE_SIZE ? MAX_NONCE_SIZE : pers.length) : 0;
		var S = Bytes.alloc(MAX_SER_SIZE);
		var blocks = serialize(S, nonce, nonceLen, pers, persLen);
		var K = Bytes.alloc(keySize);
		for (i in 0...keySize)
			K.set(i, i);
		var bccAes = new Aes();
		bccAes.init(K);
		var outputBlocks = Math.ceil(entSize / BLOCK_SIZE);
		var slab = performBCC(bccAes, S, blocks, outputBlocks);
		var finalAes = new Aes();
		finalAes.init(slab.sub(0, keySize));
		var x = Bytes.alloc(BLOCK_SIZE);
		x.blit(0, slab, keySize, BLOCK_SIZE);
		var tmp = Bytes.alloc(outputBlocks * BLOCK_SIZE);
		for (i in 0...outputBlocks) {
			finalAes.encryptBlock(x, 0, x, 0);
			tmp.blit(i * BLOCK_SIZE, x, 0, BLOCK_SIZE);
		}
		return tmp.sub(0, entSize);
	}

	private function performBCC(bccAes:Aes, S:Bytes, blocks:Int, outputBlocks:Int):Bytes {
		var slab = Bytes.alloc(outputBlocks * BLOCK_SIZE);
		for (i in 0...outputBlocks) {
			var chain = Bytes.alloc(BLOCK_SIZE);
			writeU32BE(S, 0, i);
			for (j in 0...blocks) {
				var sBlockStart = j * BLOCK_SIZE;
				for (k in 0...BLOCK_SIZE) {
					var sIndex = sBlockStart + k;
					if (sIndex < S.length) {
						chain.set(k, chain.get(k) ^ S.get(sIndex));
					}
				}
				bccAes.encryptBlock(chain, 0, chain, 0);
			}
			slab.blit(i * BLOCK_SIZE, chain, 0, BLOCK_SIZE);
		}
		return slab;
	}

	private function serialize(out:Bytes, nonce:Bytes, nonceLen:Int, pers:Bytes, persLen:Int):Int {
		var L = nonceLen + persLen;
		var size = BLOCK_SIZE + 8 + L + 1;
		if (size % BLOCK_SIZE != 0) {
			size += BLOCK_SIZE - (size % BLOCK_SIZE);
		}
		out.fill(0, size, 0);
		var pos = BLOCK_SIZE;
		writeU32BE(out, pos, L);
		pos += 4;
		writeU32BE(out, pos, entSize);
		pos += 4;
		if (nonce != null && nonceLen > 0) {
			out.blit(pos, nonce, 0, nonceLen);
			pos += nonceLen;
		}
		if (pers != null && persLen > 0) {
			out.blit(pos, pers, 0, persLen);
			pos += persLen;
		}
		out.set(pos, 0x80);
		return Math.floor(size / BLOCK_SIZE);
	}

	private inline function writeU32BE(bytes:Bytes, offset:Int, value:Int):Void {
		bytes.set(offset, (value >> 24) & 0xFF);
		bytes.set(offset + 1, (value >> 16) & 0xFF);
		bytes.set(offset + 2, (value >> 8) & 0xFF);
		bytes.set(offset + 3, value & 0xFF);
	}

	public inline function getEntropyLength():Int {
		return entSize;
	}

	public inline function getVariant():AesVariant {
		return variant;
	}

	public inline function getReseedCounter():Float {
		return reseedCounter;
	}

	public inline function needsReseed():Bool {
		return reseedCounter >= MAX_RESEED_COUNT;
	}
}
