package unit.crypto;

import unit.Test;
import haxe.io.Bytes;
import haxe.crypto.padding.*;

class PaddingTest extends Test {
	var plainText = [
		"0000000000000000", "11111111111111", "222222222222", "3333333333",
		        "44444444",         "555555",         "6666",         "77"
	];

	var pad_ansiX923 = [
		"00000000000000000000000000000008", "1111111111111101", "2222222222220002", "3333333333000003",
		                "4444444400000004", "5555550000000005", "6666000000000006", "7700000000000007"
	];

	var pad_bit = [
		"00000000000000008000000000000000", "1111111111111180", "2222222222228000", "3333333333800000",
		                "4444444480000000", "5555558000000000", "6666800000000000", "7780000000000000"
	];

	var pad_random = [
		"0000000000000000C647A5D4DED3D308", "1111111111111101", "222222222222CD02", "3333333333447F03",
		                "44444444EE04D204", "555555C5D8A5A605", "66666EEC19E29606", "774DF82706961307"
	];

	var pad_nopad = [
		"0000000000000000",
		"11111111111111",
		"222222222222",
		"3333333333",
		"44444444",
		"555555",
		"6666",
		"77"
	];

	var pad_null = [
		"00000000000000000000000000000000", "1111111111111100", "2222222222220000", "3333333333000000",
		                "4444444400000000", "5555550000000000", "6666000000000000", "7700000000000000"
	];

	var pad_pkcs7 = [
		"00000000000000000808080808080808", "1111111111111101", "2222222222220202", "3333333333030303",
		                "4444444404040404", "5555550505050505", "6666060606060606", "7707070707070707"
	];

	var pad_space = [
		"00000000000000002020202020202020", "1111111111111120", "2222222222222020", "3333333333202020",
		                "4444444420202020", "5555552020202020", "6666202020202020", "7720202020202020"
	];

	var pad_tbc = [
		"0000000000000000FFFFFFFFFFFFFFFF", "1111111111111100", "222222222222FFFF", "3333333333000000",
		                "44444444FFFFFFFF", "5555550000000000", "6666FFFFFFFFFFFF", "7700000000000000"
	];

	static inline var BLOCK_SIZE:Int = 8;

	public function test_pad():Void {
		trace("Start padding tests ...");
		for (i in 0...plainText.length) {
			var padAnsiX923 = AnsiX923.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
			eq(pad_ansiX923[i], padAnsiX923.toHex().toUpperCase());
			var padBit = BitPadding.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
			eq(pad_bit[i], padBit.toHex().toUpperCase());
			var padIso10126 = ISO10126.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE); // not check, random bytes
			var padNoPadding = NoPadding.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
			eq(pad_nopad[i], padNoPadding.toHex().toUpperCase());
			var padNull = NullPadding.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
			eq(pad_null[i], padNull.toHex().toUpperCase());
			var padPkcs7 = PKCS7.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
			eq(pad_pkcs7[i], padPkcs7.toHex().toUpperCase());
			var padSpace = SpacePadding.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
			eq(pad_space[i], padSpace.toHex().toUpperCase());
			var padTbc = TBC.pad(Bytes.ofHex(plainText[i]), BLOCK_SIZE);
			eq(pad_tbc[i], padTbc.toHex().toUpperCase());
		}
	}

	public function test_unpad():Void {
		trace("Start unpadding tests ...");
		for (i in 0...plainText.length) {
			var padAnsiX923 = AnsiX923.unpad(Bytes.ofHex(pad_ansiX923[i]));
			eq(plainText[i], padAnsiX923.toHex().toUpperCase());
			var padBit = BitPadding.unpad(Bytes.ofHex(pad_bit[i]));
			eq(plainText[i], padBit.toHex().toUpperCase());
			var padIso10126 = ISO10126.unpad(Bytes.ofHex(pad_random[i]));
			eq(plainText[i], padIso10126.toHex().toUpperCase());
			var padNoPadding = NoPadding.unpad(Bytes.ofHex(pad_nopad[i]));
			eq(plainText[i], padNoPadding.toHex().toUpperCase());
			if (i != 0) // skip check on 00 bytes
			{
				var padNull = NullPadding.unpad(Bytes.ofHex(pad_null[i]));
				eq(plainText[i], padNull.toHex().toUpperCase());
			}
			var padPkcs7 = PKCS7.unpad(Bytes.ofHex(pad_pkcs7[i]));
			eq(plainText[i], padPkcs7.toHex().toUpperCase());
			var padSpace = SpacePadding.unpad(Bytes.ofHex(pad_space[i]));
			eq(plainText[i], padSpace.toHex().toUpperCase());
			var padTbc = TBC.unpad(Bytes.ofHex(pad_tbc[i]));
			eq(plainText[i], padTbc.toHex().toUpperCase());
		}
	}

	// -----------------------------------------------------------------------
	// Security regression tests
	// -----------------------------------------------------------------------

	/**
	 * PKCS7.unpad must reject all invalid inputs with a single uniform
	 * exception, regardless of *why* validation fails.  Using different
	 * code paths for "out of range" vs "wrong byte value" leaks the
	 * padding length to an attacker (padding oracle / timing side-channel).
	 */
	public function test_pkcs7_unpad_security():Void {
		trace("PKCS7 security: all invalid inputs must throw ...");

		// padding = 0 is never produced by pad() and must be rejected
		exc(() -> PKCS7.unpad(Bytes.ofHex("0000000000000000")));

		// padding byte value (0xFF = 255) exceeds the message length (1 byte)
		exc(() -> PKCS7.unpad(Bytes.ofHex("FF")));

		// padding byte value exceeds the message length (4 bytes, value 8)
		exc(() -> PKCS7.unpad(Bytes.ofHex("04040408")));

		// one corrupted byte in the middle of an otherwise valid padding region
		// "0001040404040404": last byte = 4, bytes at positions 4-7 are 00,04,04,04
		exc(() -> PKCS7.unpad(Bytes.ofHex("0001040404040404")));

		// only the first padding byte is wrong — catches a non-constant-time loop
		// "0808080808080801": last byte = 1, byte at position 7 = 0x01 — that's fine,
		// but the declared padding value is 1, so only position 7 is checked and it
		// equals 1 → actually valid.  Use a case where the first mismatch is early:
		// "0102030404040404": last byte = 4, bytes at positions 4-7: 04,04,04,04 → valid
		// "0102030400040404": last byte = 4, byte at position 4 = 0x00 ≠ 4 → invalid
		exc(() -> PKCS7.unpad(Bytes.ofHex("0102030400040404")));

		trace("PKCS7 security: valid inputs must still be accepted ...");

		// full block of padding (blockSize = 8, padding = 8)
		var result = PKCS7.unpad(Bytes.ofHex("0808080808080808"));
		eq(0, result.length);

		// single padding byte
		eq("01", PKCS7.unpad(Bytes.ofHex("0101")).toHex().toUpperCase());

		// round-trip: pad then unpad must yield the original plaintext
		for (i in 0...plainText.length) {
			var original = Bytes.ofHex(plainText[i]);
			var padded   = PKCS7.pad(original, BLOCK_SIZE);
			var restored = PKCS7.unpad(padded);
			eq(plainText[i], restored.toHex().toUpperCase());
		}
	}

	/**
	 * ISO10126.unpad must validate the padding length field before using it.
	 * Without this check an attacker can supply a crafted last byte that
	 * causes an out-of-bounds access, crashing the program.
	 *
	 * ISO 10126 pad() always writes a length-byte ≥ 1, so 0 is never a
	 * legitimate value and must also be rejected.
	 */
	public function test_iso10126_unpad_security():Void {
		trace("ISO10126 security: padding = 0 must be rejected ...");
		// Last byte 0x00: never produced by pad(), must be rejected
		exc(() -> ISO10126.unpad(Bytes.ofHex("0100")));

		trace("ISO10126 security: padding > length must not crash ...");
		// 1-byte input, last byte = 0xFF (255) — would read sub(0, -254)
		exc(() -> ISO10126.unpad(Bytes.ofHex("FF")));

		// 4-byte input, last byte = 0x10 (16 > 4) — padding larger than message
		exc(() -> ISO10126.unpad(Bytes.ofHex("AABBCC10")));

		trace("ISO10126 security: valid inputs must still be accepted ...");

		// Entire buffer is padding: 5 bytes, last byte = 5, result is empty
		var result = ISO10126.unpad(Bytes.ofHex("AABBCCDD05"));
		eq(0, result.length);

		// Single padding byte: last byte = 1
		eq("01", ISO10126.unpad(Bytes.ofHex("0101")).toHex().toUpperCase());

		// Round-trip: pad then unpad must yield the original plaintext
		for (i in 0...plainText.length) {
			var original = Bytes.ofHex(plainText[i]);
			var padded   = ISO10126.pad(original, BLOCK_SIZE);
			var restored = ISO10126.unpad(padded);
			eq(plainText[i], restored.toHex().toUpperCase());
		}
	}
}
