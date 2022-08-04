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

import haxe.math.bigint.BigInt;
import haxe.math.bigint.BigIntArithmetic;
import haxe.math.bigint.BigIntTools;
import haxe.math.bigint.MultiwordArithmetic;
import haxe.crypto.ec.IEllipticCurve;
import haxe.crypto.ec.IEllipticCurvePoint;
import haxe.math.bigint.BigIntExceptions;
import haxe.crypto.ec.modular.IModularField;
import haxe.crypto.ec.modular.IModularInt;
import haxe.crypto.ec.modular.impl.PrimeField;
import haxe.ds.Vector;

/* Original code courtesy Chuck Batson (github.com/cbatson) */
class GeneralAffinePrimeCurve implements IEllipticCurve
{
	public function get_G() : IEllipticCurvePoint
	{
		return m_G;
	}

	public function get_order() : BigInt
	{
		return m_order;
	}

	public function getField() : IModularField
	{
		return m_field;
	}

	public function newPoint(x : Dynamic, y : Dynamic) : IEllipticCurvePoint
	{
		var pt = new GeneralAffinePrimePoint(this);
		pt.m_x = m_field.newInt(x);
		pt.m_y = m_field.newInt(y);
		return pt;
	}

	public function newCopy(input : IEllipticCurvePoint) : IEllipticCurvePoint
	{
		return _newCopy(_check(input));
	}

	private function _newCopy(input : GeneralAffinePrimePoint) : IEllipticCurvePoint
	{
		var pt = new GeneralAffinePrimePoint(this);
		pt.m_x = m_field.newInt(input.m_x);
		pt.m_y = m_field.newInt(input.m_y);
		return pt;
	}

	public function pointAdd(result : IEllipticCurvePoint, operand1 : IEllipticCurvePoint, operand2 : IEllipticCurvePoint) : Void
	{
		_pointAdd(_check(result), _check(operand1), _check(operand2));
	}

	private function _pointAdd(result : GeneralAffinePrimePoint, operand1 : GeneralAffinePrimePoint, operand2 : GeneralAffinePrimePoint) : Void
	{
		if (_isInfinity(operand1))
		{
			_copy(result, operand2);
		}
		else if (_isInfinity(operand2))
		{
			_copy(result, operand1);
		}
		else
		{
			m_field.subtract(m_work2, operand2.m_x, operand1.m_x);
			if (m_field.isZero(m_work2))
			{
				_getInfinity(result);
			}
			else
			{
				m_field.subtract(m_work1, operand2.m_y, operand1.m_y);
				m_field.divide(m_work3, m_work1, m_work2);
				m_field.square(m_work2, m_work3);
				m_field.subtract(m_work2, m_work2, operand1.m_x);
				m_field.subtract(m_work2, m_work2, operand2.m_x);
				m_field.subtract(m_work1, operand1.m_x, m_work2);
				m_field.multiply(m_work3, m_work3, m_work1);
				m_field.subtract(result.m_y, m_work3, operand1.m_y);
				m_field.copy(result.m_x, m_work2);
			}
		}
	}

	public function pointDouble(result : IEllipticCurvePoint, operand : IEllipticCurvePoint) : Void
	{
		_pointDouble(_check(result), _check(operand));
	}

	private function _pointDouble(result : GeneralAffinePrimePoint, operand : GeneralAffinePrimePoint) : Void
	{
		if (_isInfinity(operand))
		{
			_copy(result, operand);
		}
		else if (m_field.isZero(operand.m_y))
		{
			_getInfinity(result);
		}
		else
		{
			m_field.square(m_work1, operand.m_x);
			m_field.add(m_work2, m_work1, m_work1);
			m_field.add(m_work2, m_work2, m_work1);
			m_field.add(m_work2, m_work2, m_a);
			m_field.add(m_work3, operand.m_y, operand.m_y);
			m_field.divide(m_work1, m_work2, m_work3);	// work1 = lambda
			m_field.square(m_work3, m_work1);
			m_field.subtract(m_work3, m_work3, operand.m_x);
			m_field.subtract(m_work3, m_work3, operand.m_x);
			m_field.subtract(m_work2, operand.m_x, m_work3);
			m_field.multiply(m_work1, m_work1, m_work2);
			m_field.subtract(result.m_y, m_work1, operand.m_y);
			m_field.copy(result.m_x, m_work3);
		}
	}

	public function pointMultiply(result : IEllipticCurvePoint, operand1 : IEllipticCurvePoint, operand2 : Dynamic) : Void
	{
		var op2 = BigIntTools.parseValueUnsigned(operand2);
		_pointMultiply(_check(result), _check(operand1), op2);
	}

	private function _pointMultiply(result : GeneralAffinePrimePoint, operand1 : GeneralAffinePrimePoint, operand2 : BigInt) : Void
	{
		// Implements Algorithm 3.27 (p. 97) from "Guide to Elliptic Curve Cryptography"; Hankerson, Menezes, and Vanstone; 2004.

		if (operand2.isNegative())
		{
			throw BigIntExceptions.INVALID_ARGUMENT;
		}

		var numBits : Int = BigIntArithmetic.floorLog2(operand2);
		_getInfinity(result);
		while (--numBits >= 0)
		{
			_pointDouble(result, result);
			if (operand2.getBit(numBits) != 0)
			{
				_pointAdd(result, result, operand1);
			}
		}
	}

	public function newInfinity() : IEllipticCurvePoint
	{
		var pt = new GeneralAffinePrimePoint(this);
		pt.m_x = m_field.newInt(0);
		pt.m_y = m_field.newInt(0);
		return pt;
	}

	private function _getInfinity(result : GeneralAffinePrimePoint) : Void
	{
		m_field.setZero(result.m_x);
		m_field.setZero(result.m_y);
	}

	public function isInfinity(point : IEllipticCurvePoint) : Bool
	{
		return _isInfinity(_check(point));
	}

	private function _isInfinity(point : GeneralAffinePrimePoint) : Bool
	{
		return m_field.isZero(point.m_x) && m_field.isZero(point.m_y);
	}

	private function _copy(result : GeneralAffinePrimePoint, from : GeneralAffinePrimePoint) : Void
	{
		if (result != from)
		{
			m_field.copy(result.m_x, from.m_x);
			m_field.copy(result.m_y, from.m_y);
		}
	}

	public function clear() : Void
	{
		m_work1.clear();
		m_work2.clear();
		m_work3.clear();
		if (m_buf != null) {
			MultiwordArithmetic.setZero(m_buf, m_buf.length);
		}
	}

	public function new(field : PrimeField, a : Dynamic, b : Dynamic, Gx : Dynamic, Gy : Dynamic, order : Dynamic)
	{
		m_field = field;
		m_a = m_field.newInt(a);
		m_b = m_field.newInt(b);
		m_G = cast newPoint(Gx, Gy);
		m_order = BigIntTools.parseValueUnsigned(order);
		m_work1 = m_field.newInt();
		m_work2 = m_field.newInt();
		m_work3 = m_field.newInt();
		m_buf = new Vector<Int>(m_a.toInts(null));
	}

	private inline function _check(p : IEllipticCurvePoint) : GeneralAffinePrimePoint
	{
		if (p.getCurve() != this)
		{
			throw BigIntExceptions.INVALID_ARGUMENT;
		}
		return cast p;
	}

	private var m_field : IModularField;
	private var m_a : IModularInt;
	private var m_b : IModularInt;
	private var m_G : GeneralAffinePrimePoint;
	private var m_order : BigInt;

	private var m_work1 : IModularInt;
	private var m_work2 : IModularInt;
	private var m_work3 : IModularInt;

	private var m_buf : Vector<Int>;
}
