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
import haxe.ds.Vector;

/* Original code courtesy Chuck Batson (github.com/cbatson) */
@:allow(haxe.crypto.ec.modular)
class ModularInt implements IModularInt
{
	public function toHex() : String
	{
		return MultiwordArithmetic.toHex(m_value, m_value.length);
	}

	public function toString() : String
	{
		return MultiwordArithmetic.toDecimalUnsigned(m_value, m_value.length);
	}

	public function toInts(output : Vector<Int>) : Int
	{
		if (output != null)
		{
			var n : Int =  (output.length < m_value.length) ? output.length : m_value.length;
			Vector.blit(m_value, 0, output, 0, n);
		}
		return m_value.length;
	}

	public function getField() : IModularField
	{
		return m_field;
	}

	public function clear() : Void
	{
		zero();
	}

	private inline function zero() : Void
	{
		MultiwordArithmetic.setZero(m_value, m_value.length);
	}

	private function isOne() : Bool
	{
		if (m_value.get(0) != 1)
		{
			return false;
		}
		for (i in 1 ... m_value.length)
		{
			if (m_value.get(i) != 0)
			{
				return false;
			}
		}
		return true;
	}

	private function new(field : ModularField, numWords : Int) : Void
	{
		m_field = field;
		m_value = new Vector<Int>(numWords);
	}

	private var m_value : Vector<Int>;
	private var m_field : ModularField;
}
