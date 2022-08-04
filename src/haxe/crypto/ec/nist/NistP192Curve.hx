/*
 * Copyright (C)2005-2022 Haxe Foundation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
package haxe.crypto.ec.nist;

import haxe.crypto.ec.IEllipticCurvePoint;
import haxe.crypto.ec.impl.GeneralAffinePrimeCurve;
import haxe.crypto.ec.modular.IModularInt;
import haxe.crypto.ec.modular.impl.PrimeField;

/* Original code courtesy Chuck Batson (github.com/cbatson) */
class NistP192Curve extends GeneralAffinePrimeCurve
{
	public function new()
	{
		// Parameters from http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
		// Retrieved 17 Nov 2014
		super(
			new PrimeField("6277101735386680763835789423207666416083908700390324961279"),
			-3,																// a
			"0x 64210519 e59c80e7 0fa7e9ab 72243049 feb8deec c146b9b1",		// b
			"0x 188da80e b03090f6 7cbf20eb 43a18800 f4ff0afd 82ff1012",		// Gx
			"0x 07192b95 ffc8da78 631011ed 6b24cdd5 73f977a1 1e794811",		// Gy
			"6277101735386680763835789423176059013767194773182842284081"	// order
		);
	}
}
