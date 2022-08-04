package haxe.crypto.ec.nist;

import haxe.crypto.ec.IEllipticCurvePoint;
import haxe.crypto.ec.impl.GeneralAffinePrimeCurve;
import haxe.crypto.ec.modular.IModularInt;
import haxe.crypto.ec.modular.impl.PrimeField;

/* Original code courtesy Chuck Batson (github.com/cbatson) */
class NistP384Curve extends GeneralAffinePrimeCurve
{
	public function new()
	{
		// Parameters from http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
		// Retrieved 17 Nov 2014
		super(
			new PrimeField("39402006196394479212279040100143613805079739270465446667948293404245721771496870329047266088258938001861606973112319"),
			-3,																														// a
			"0x b3312fa7 e23ee7e4 988e056b e3f82d19 181d9c6e fe814112 0314088f 5013875a c656398d 8a2ed19d 2a85c8ed d3ec2aef",		// b
			"0x aa87ca22 be8b0537 8eb1c71e f320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7",		// Gx
			"0x 3617de4a 96262c6f 5d9e98bf 9292dc29 f8f41dbd 289a147c e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f",		// Gy
			"39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643"	// order
		);
	}
}
