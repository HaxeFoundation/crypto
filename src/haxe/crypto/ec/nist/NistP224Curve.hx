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
class NistP224Curve extends GeneralAffinePrimeCurve
{
	public function new()
	{
		// Parameters from http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
		// Retrieved 17 Nov 2014
		super(
			new PrimeField("26959946667150639794667015087019630673557916260026308143510066298881"),
			-3,																		// a
			"0x b4050a85 0c04b3ab f5413256 5044b0b7 d7bfd8ba 270b3943 2355ffb4",	// b
			"0x b70e0cbd 6bb4bf7f 321390b9 4a03c1d3 56c21122 343280d6 115c1d21",	// Gx
			"0x bd376388 b5f723fb 4c22dfe6 cd4375a0 5a074764 44d58199 85007e34",	// Gy
			"26959946667150639794667015087019625940457807714424391721682722368061"	// order
		);
	}
}
