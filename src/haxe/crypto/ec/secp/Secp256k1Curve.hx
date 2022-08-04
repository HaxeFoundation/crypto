package haxe.crypto.ec.secp;

import haxe.crypto.ec.IEllipticCurvePoint;
import haxe.crypto.ec.impl.GeneralAffinePrimeCurve;
import haxe.crypto.ec.modular.IModularInt;
import haxe.crypto.ec.modular.impl.PrimeField;

/* Original code courtesy Chuck Batson (github.com/cbatson) */
class Secp256k1Curve extends GeneralAffinePrimeCurve
{
	/*
		The elliptic curve domain parameters over Fp associated with a Koblitz curve secp256k1 are
		specified by the sextuple T = (p, a, b, G, n, h) where the finite field Fp is defined by:

			p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
			  = 2^256 − 2^32 − 2^9 − 2^8 − 2^7 − 2^6 − 2^4 − 1

		The curve E: y^2 = x^3 + ax + b over Fp is defined by:

			a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
			b = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007

		The base point G in compressed form is:

			G = 02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798

		and in uncompressed form is:

			G = 04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8

		Finally the order n of G and the cofactor are:

			n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141

			h = 01

		(Parameters from http://www.secg.org/sec2-v2.pdf retrieved 2014.11.08)
	*/
	public function new()
	{
		super(
			new PrimeField("0x FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F"),
			0,	// a
			7,	// b
			"0x 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798",	// Gx
			"0x 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8",	// Gy
			"0x FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"	// order
		);
	}
}
