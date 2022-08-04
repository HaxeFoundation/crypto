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
package  haxe.crypto.ec.modular;

import haxe.math.bigint.BigInt;

/* Original code courtesy Chuck Batson (github.com/cbatson) */
interface IModularField
{
	/**
		Returns the modulus for this field.
	**/
	function getModulus() : BigInt;

	/**
		Creates a new integer value in this field.

		Acceptable types for input `value` are `Int`,
		`BigInt`, `MutableBigInt`, `IModularInt`,
		and `null`.
	**/
	function newInt(value : Dynamic = null) : IModularInt;

	/**
		Sets the value of an integer in this field to zero.
	**/
	function setZero(result : IModularInt) : Void;

	/**
		Sets the value of an integer in this field.

		Acceptable types for input `value` are `Int`,
		`BigInt`, `MutableBigInt`, `IModularInt`,
		and `null`.
	**/
	function setInt(result : IModularInt, value : Dynamic) : Void;

	/**
		Copy the value from one integer in this field to another.
	**/
	function copy(result : IModularInt, from : IModularInt) : Void;

	/**
		Returns `true` if the integer from this field `input`
		represents a value of 0; `false` otherwise.
	**/
	function isZero(input : IModularInt) : Bool;

	/**
		Compare two values from this field.

		If `a < b` the result is -1.
		If `a == b` the result is 0.
		If `a > b` the result is 1.
	**/
	function compare(a : IModularInt, b : IModularInt) : Int;

	/**
		Add the field integers `operand1` and `operand2` and store
		the result in `result`.

		`result` may refer to the inputs `operand1` and/or
		`operand2`.

		`operand1` and `operand2` may refer to the same object.

		All arguments must be integers from this field.
	**/
	function add(result : IModularInt, operand1 : IModularInt, operand2 : IModularInt) : Void;

	/**
		Subtract the field integer `operand2` from `operand1` and
		store the result in `result`.

		`result` may refer to the inputs `operand1` and/or
		`operand2`.

		`operand1` and `operand2` may refer to the same object.

		All arguments must be integers from this field.
	**/
	function subtract(result : IModularInt, operand1 : IModularInt, operand2 : IModularInt) : Void;

	/**
		Square the field integer `operand` and store the result in
		`result`.

		`result` and `operand` may refer to the same object.

		All arguments must be integers from this field.
	**/
	function square(result : IModularInt, operand : IModularInt) : Void;

	/**
		Multiply the field integers `operand1` and `operand2` and
		store the result in `result`.

		`result` may refer to the inputs `operand1` and/or
		`operand2`.

		`operand1` and `operand2` may refer to the same object.

		All arguments must be integers from this field.
	**/
	function multiply(result : IModularInt, operand1 : IModularInt, operand2 : IModularInt) : Void;

	/**
		Divide the field integer `dividend` by `divisor` and
		store the result in `result`.

		That is to say, this function finds `result` such that
		`result` * `divisor` = `dividend` modulo M, where M
		is this field's modulus.

		In other words, `result` = `dividend` * `divisor`<sup>-1</sup>.

		`result` may refer to the inputs `dividend` and/or
		`divisor`.

		`dividend` and `divisor` may refer to the same object.

		All arguments must be integers from this field.
	**/
	function divide(result : IModularInt, dividend : IModularInt, divisor : IModularInt) : Void;

	/**
		Reduce an arbitrary integer `input` into this field.
	**/
	function reduce(result : IModularInt, input : BigInt) : Void;
}
