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

import haxe.math.bigint.MultiwordArithmetic;
import haxe.math.bigint.MutableBigInt;
import haxe.crypto.ec.modular.ModularExceptions;
import haxe.crypto.ec.modular.IModularField;
import haxe.crypto.ec.modular.ModularFields;

/* Original code courtesy Chuck Batson (github.com/cbatson) */
@:allow(haxe.crypto.ec.modular)
class PrimeField extends ModularField implements IModularField
{
	public override function divide(result : IModularInt, dividend : IModularInt, divisor : IModularInt) : Void
	{
		_divide(_check(result), _check(dividend), _check(divisor));
	}

	private function _divide(result : ModularInt, dividend : ModularInt, divisor : ModularInt) : Void
	{
		// Implements Algorithm 2.22 (p. 41) from "Guide to Elliptic Curve Cryptography"; Hankerson, Menezes, and Vanstone; 2004.

		// TODO: Better understand the bounds of intermediate values in this algoritm.
		// Or, look for algorithms where the bounds of values are well-defined, for example,
		// if all operations occur over the field.
		// This might be one:
		//	"A hardware algorithm for modular multiplication/division"
		//	Kaihara, M.E.; Takagi, N.
		//	http://ieeexplore.ieee.org/xpl/articleDetails.jsp?partnum=1362636

		if (_isZero(divisor))
		{
			throw ModularExceptions.INVALID_OPERATION;
		}

		m_u.setFromUnsignedInts(divisor.m_value, m_numWords);
		m_v.copyFrom(m_modulusBI);
		m_x1.setFromUnsignedInts(dividend.m_value, m_numWords);
		m_x2.setFromInt(0);
		while ((m_u != 1) && (m_v != 1))
		{
			while ((m_u & 1) == 0)
			{
				m_u >>= 1;
				if ((m_x1 & 1) != 0)
				{
					m_x1 += m_modulusBI;
				}
				m_x1 >>= 1;
			}
			while ((m_v & 1) == 0)
			{
				m_v >>= 1;
				if ((m_x2 & 1) != 0)
				{
					m_x2 += m_modulusBI;
				}
				m_x2 >>= 1;
			}
			if (m_u >= m_v)
			{
				m_u -= m_v;
				m_x1 -= m_x2;
			}
			else
			{
				m_v -= m_u;
				m_x2 -= m_x1;
			}
		}
		if (m_u == 1)
		{
			_reduce(result, m_x1);
		}
		else
		{
			_reduce(result, m_x2);
		}
	}

	public function new(modulus : Dynamic) : Void
	{
		super(modulus);
		m_u = 0;
		m_v = 0;
		m_x1 = 0;
		m_x2 = 0;
	}

	private var m_u : MutableBigInt;
	private var m_v : MutableBigInt;
	private var m_x1 : MutableBigInt;
	private var m_x2 : MutableBigInt;
}
