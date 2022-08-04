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
package haxe.crypto.ec.modular.impl;

import haxe.math.bigint.BigInt;
import haxe.math.bigint.BigIntArithmetic;
import haxe.math.bigint.BigIntTools;
import haxe.math.bigint.MultiwordArithmetic;
import haxe.math.bigint.MutableBigInt;
import haxe.crypto.ec.modular.ModularExceptions;
import haxe.crypto.ec.modular.IModularField;
import haxe.crypto.ec.modular.IModularInt;
import haxe.crypto.ec.modular.ModularFields;
import haxe.ds.Vector;

/* Original code courtesy Chuck Batson (github.com/cbatson) */
class ModularField implements IModularField
{
	public function divide(result : IModularInt, dividend : IModularInt, divisor : IModularInt) : Void
	{
		throw ModularExceptions.INVALID_OPERATION;
	}

	public function square(result : IModularInt, operand : IModularInt) : Void
	{
		var o = _check(operand);
		_multiply(_check(result), o, o);
	}

	public function multiply(result : IModularInt, operand1 : IModularInt, operand2 : IModularInt) : Void
	{
		_multiply(_check(result), _check(operand1), _check(operand2));
	}

	private function _multiply(result : ModularInt, operand1 : ModularInt, operand2 : ModularInt) : Void
	{
		_copy(m_work2, operand1);
		_setZero(m_work3);
		for (i in 0 ... m_numBits)
		{
			if (MultiwordArithmetic.getBitSigned(operand2.m_value, m_numWords, i) != 0)
			{
				_add(m_work3, m_work3, m_work2);
			}
			_add(m_work2, m_work2, m_work2);	// double
		}
		_copy(result, m_work3);
	}

	public function add(result : IModularInt, operand1 : IModularInt, operand2 : IModularInt) : Void
	{
		_add(_check(result), _check(operand1), _check(operand2));
	}

	private function _add(result : ModularInt, operand1 : ModularInt, operand2 : ModularInt) : Void
	{
		// Implements Algorithm 2.7 (p. 31) from "Guide to Elliptic Curve Cryptography"; Hankerson, Menezes, and Vanstone; 2004.
		var c =  MultiwordArithmetic.add(result.m_value, operand1.m_value, operand2.m_value, m_numWords);
		if ((c != 0) || (_compare(result, m_modulusMI) >= 0))
		{
			 MultiwordArithmetic.subtract(result.m_value, result.m_value, m_modulusMI.m_value, m_numWords);
		}
	}

	public function subtract(result : IModularInt, operand1 : IModularInt, operand2 : IModularInt) : Void
	{
		_subtract(_check(result), _check(operand1), _check(operand2));
	}

	private function _subtract(result : ModularInt, operand1 : ModularInt, operand2 : ModularInt) : Void
	{
		// Implements Algorithm 2.8 (p. 31) from "Guide to Elliptic Curve Cryptography"; Hankerson, Menezes, and Vanstone; 2004.
		var c =  MultiwordArithmetic.subtract(result.m_value, operand1.m_value, operand2.m_value, m_numWords);
		if (c != 0)
		{
			 MultiwordArithmetic.add(result.m_value, result.m_value, m_modulusMI.m_value, m_numWords);
		}
	}

	public function reduce(result : IModularInt, input :  BigInt) : Void
	{
		_reduce(_check(result), input);
	}

	private function _reduce(result : ModularInt, input :  BigInt) : Void
	{
		 BigIntArithmetic.divide(input, m_modulusBI, m_quotient, m_remainder, m_work);
		if (m_remainder.isNegative())
		{
			 BigIntArithmetic.add(m_remainder, m_remainder, m_modulusBI);
		}
		var num : Int = m_remainder.toInts(result.m_value);
		for (i in num ... m_numWords)
		{
			result.m_value.set(i, 0);
		}
	}

	public function compare(a : IModularInt, b : IModularInt) : Int
	{
		return _compare(_check(a), _check(b));
	}

	private inline function _compare(a : ModularInt, b : ModularInt) : Int
	{
		return  MultiwordArithmetic.compareUnsigned(a.m_value, b.m_value, m_numWords);
	}

	public function getModulus() :  BigInt
	{
		return m_modulusBI;
	}

	public function newInt(value : Dynamic = null) : IModularInt
	{
		return _newInt(value, true);
	}

	private function _newInt(value : Dynamic, doReduce : Bool) : ModularInt
	{
		var result = new ModularInt(this, m_numWords);
		if (value != null)
		{
			_setInt(result, value, doReduce);
		}
		return result;
	}

	public function copy(result : IModularInt, from : IModularInt) : Void
	{
		_copy(_check(result), _check(from));
	}

	private inline function _copy(result : ModularInt, from : ModularInt) : Void
	{
		if (result != from)
		{
			Vector.blit(from.m_value, 0, result.m_value, 0, m_numWords);
		}
	}

	public function setZero(result : IModularInt) : Void
	{
		_setZero(_check(result));
	}

	private function _setZero(result : ModularInt) : Void
	{
		for (i in 0 ... m_numWords)
		{
			result.m_value.set(i, 0);
		}
	}

	public function isZero(input : IModularInt) : Bool
	{
		return _isZero(_check(input));
	}

	private function _isZero(input : ModularInt) : Bool
	{
		for (i in 0 ... m_numWords)
		{
			if (input.m_value.get(i) != 0)
			{
				return false;
			}
		}
		return true;
	}

	public function setInt(result : IModularInt, value : Dynamic) : Void
	{
		_setInt(_check(result), value, true);
	}

	private function _setInt(result : ModularInt, value : Dynamic, doReduce : Bool) : Void
	{
		if (value == null)
		{
			throw ModularExceptions.NULL_ARGUMENT;
		}
		var bi :  BigInt;
		if (Std.isOfType(value, IModularInt))
		{
			var mi : IModularInt = cast value;
			if (mi.getField() == this)
			{
				_copy(result, cast mi);
				return;
			}
			// TODO: Allow modular ints from other fields?
			throw ModularExceptions.INVALID_ARGUMENT;
		}
		else
		{
			bi =  BigIntTools.parseValueUnsigned(value);
		}
		if (doReduce)
		{
			reduce(result, bi);
		}
		else
		{
			bi.toInts(result.m_value);
		}
	}

	private function new(modulus : Dynamic) : Void
	{
		m_modulusBI =  BigIntTools.parseValueUnsigned(modulus);
		if (m_modulusBI < 2)
		{
			throw ModularExceptions.INVALID_ARGUMENT;
		}

		m_quotient = 0;
		m_remainder = 0;
		m_work = 0;

		m_numBits =  BigIntArithmetic.floorLog2(m_modulusBI - 1);
		m_numWords = (m_numBits + 31) >> 5;
		m_modulusMI = _newInt(m_modulusBI, false);

		m_work2 = _newInt(null, false);
		m_work3 = _newInt(null, false);
	}

	private inline function _check(value : IModularInt) : ModularInt
	{
		if (value.getField() != this)
		{
			throw ModularExceptions.INVALID_ARGUMENT;
		}
		return cast value;
	}

	private var m_numWords : Int;
	private var m_numBits : Int;
	private var m_modulusBI :  BigInt;
	private var m_modulusMI : ModularInt;

	private var m_quotient : MutableBigInt;
	private var m_remainder : MutableBigInt;
	private var m_work : MutableBigInt;
	private var m_work2 : ModularInt;
	private var m_work3 : ModularInt;
}
