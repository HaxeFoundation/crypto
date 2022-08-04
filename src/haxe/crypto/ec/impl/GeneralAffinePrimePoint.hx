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
package haxe.crypto.ec.impl;

import haxe.crypto.ec.IEllipticCurve;
import haxe.crypto.ec.modular.IModularInt;

/* Original code courtesy Chuck Batson (github.com/cbatson) */
@:allow(haxe.crypto.ec.impl)
class GeneralAffinePrimePoint implements IEllipticCurvePoint
{
	public function get_x() : IModularInt
	{
		return m_x;
	}

	public function get_y() : IModularInt
	{
		return m_y;
	}

	public function getCurve() : IEllipticCurve
	{
		return m_curve;
	}

	public function toString() : String
	{
		return "(" + m_x + "," + m_y + ")";
	}

	private function new(curve : GeneralAffinePrimeCurve)
	{
		m_curve = curve;
	}

	private var m_x : IModularInt;
	private var m_y : IModularInt;
	private var m_curve : GeneralAffinePrimeCurve;
}
