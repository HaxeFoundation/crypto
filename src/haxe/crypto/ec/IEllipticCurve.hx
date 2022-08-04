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
package haxe.crypto.ec;

import haxe.math.bigint.BigInt;
import haxe.crypto.ec.modular.IModularField;
import haxe.crypto.ec.modular.IModularInt;

/* Original code courtesy Chuck Batson (github.com/cbatson) */
interface IEllipticCurve
{
	function get_G() : IEllipticCurvePoint;

	function get_order() : BigInt;

	/**
		Get the field over which this curve is defined.
	**/
	function getField() : IModularField;

	function newPoint(x : Dynamic, y : Dynamic) : IEllipticCurvePoint;

	function newCopy(input : IEllipticCurvePoint) : IEllipticCurvePoint;

	function newInfinity() : IEllipticCurvePoint;

	function isInfinity(point : IEllipticCurvePoint) : Bool;

	/**
		Perform a point addition operation on this curve.

		`result` may be the same object as `operand1` or `operand2`.
	**/
	function pointAdd(result : IEllipticCurvePoint, operand1 : IEllipticCurvePoint, operand2 : IEllipticCurvePoint) : Void;

	/**
		Perform a point doubling operation on this curve.

		`result` and `operand` may be the same object.
	**/
	function pointDouble(result : IEllipticCurvePoint, operand : IEllipticCurvePoint) : Void;

	function pointMultiply(result : IEllipticCurvePoint, operand1 : IEllipticCurvePoint, operand2 : Dynamic) : Void;
}
