#pragma once

/*
This file contains a collection of non-cryptographic random number generators, each with different characteristics
and use cases. The implementations are designed to be efficient, high-quality, and suitable for a wide range of 
applications such as simulations, games, and randomized algorithms.

Security Warning: These generators are NOT designed for cryptographic use. 

Contents:
	uint64_t mx3(uint64_t x) - Jon Maiga's mixing function
	uint64_t better_rand_device() - Improved random seed generator, combines std::random_device with other entropy sources.
	class wyrand - Weyl-Mix RNG. The original 64-bit version of wyrand, very fast, high qualty
	class wy256 - Weyl-Mix RNG. 256 bit state, uses wyrand mixing function, with 2^256 period and strong streaming support
	class SplitMix64 - LCG/Permuted RNG. The classic 64 bit RNG
	class xoshiro256plusplus - Shift-Register RNG. 2019 by David Blackman and Sebastiano Vigna - A high-quality 256 bit state NCPRNG.

The copyright notice for xoshiro256plusplus is embedded in the class definition.

All other code is this file is released to the public domain by the author, under the MIT License:

	Copyright 2026 Jim Staley

	Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated 
	documentation files (the “Software”), to deal in the Software without restriction, including without limitation 
	the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, 
	and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all copies or substantial portions 
	of the Software.

	THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED 
	TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL 
	THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
	CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER 
	DEALINGS IN THE SOFTWARE.
*/

#include "RNG_primitives.h"
#include "RNG_SplitMix64.h"
#include "RNG_wyrand.h"
#include "RNG_wy256.h"
#include "RNG_xoshiro256plusplus.h"

