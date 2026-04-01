#pragma once
#include "RNG_SplitMix64.h"

/*
The original code and algorithm for xoshiro256++ was designed by David Blackman and Sebastiano Vigna, and is available
at
    https://prng.di.unimi.it/xoshiro256plusplus.c

The changes made in this implementation are as follows:
1. Encapsulated in a c++ class.
2. Addded seeding functions: 1 uint64_t seed, 2 uint64_t seeds, and non-deterministic seeding.
3. Added draw32(), draw64(), uniform(), and uni() functions for convenience.
4. Added a factory function for creating multiple independent generators for parallel use.
5. Added result_type, min(), and max() for compatibility with C++ random library conventions.

These changes are Copyright 2026 Jim Staley

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files(the “Software”), to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and /or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so, subject to the following conditions :

The above copyright notice and this permission notice shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

namespace RNG {

	class xoshiro256plusplus {
		/*
		 * xoshiro256++ 1.0 - All-purpose, rock-solid 256-bit generator.
		 * Designed by David Blackman and Sebastiano Vigna.
		 *
		 * Blackmans and Vigna's original code is available at
		 *		https://prng.di.unimi.it/xoshiro256plusplus.c
		 *
		 * The original copyright statement is as follows:
		 *		Written in 2019 by David Blackman and Sebastiano Vigna (vigna@acm.org)
		 *
		 *		To the extent possible under law, the author has dedicated all copyright
		 *		and related and neighboring rights to this software to the public domain
		 *		worldwide.
		 *
		 *		Permission to use, copy, modify, and/or distribute this software for any
		 *		purpose with or without fee is hereby granted.
		 *
		 *		THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
		 *		WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
		 *		MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
		 *		ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
		 *		WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
		 *		ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
		 *		IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
		 */
		using MyT = xoshiro256plusplus;
		u64 s[4]; // State must not be all-zero

	public:
		using result_type = u64;

		//--------------------------
		// Construct, destruct, seed
		//--------------------------
		// Deterministic constructor
		xoshiro256plusplus(u64 seed_val) noexcept { seed(seed_val); }
		xoshiro256plusplus(u64 seed_val1, u64 seedval2) noexcept { seed(seed_val1, seedval2); }

		// Non-deterministic constructor.
		xoshiro256plusplus() noexcept { seed(); }

		// Seed function for state initialization. Uses SplitMix64 to fill the 256-bit state from a 
		// single 64-bit seed value, as recommended by the authors.
		constexpr MyT& seed(u64 seed_val) noexcept {
			return seed(seed_val, 0xf39cc0605cedc834ull);
		}

		constexpr MyT& seed(u64 seed_val1, u64 seed_val2) noexcept {
			// Filling the 256-bit state using SplitMix64 (as recommended by authors).
			// But please note: the use of the discard function here is a non-standard 
			// approach to further mix the state with the second seed value, and is not
			// part of the original recommendation. However, it provides us a way to 
			// incorporate up to 128 bits of seed material while still using SplitMix64
			// for state filling.
			SplitMix64 gen1(Primitives::pelican(seed_val1));
			SplitMix64 gen2(Primitives::pelican(seed_val2));

			uint64_t counter = 0xa2e834c5893a39ebull; // bits 64-127 of the golden ratio
			s[0] = gen1(); gen1.discard(gen2() ^ (counter += 0x9e3779b97f4a7c15ull)); gen2.discard(gen1());
			s[1] = gen1(); gen1.discard(gen2() ^ (counter += 0x9e3779b97f4a7c15ull)); gen2.discard(gen1());
			s[2] = gen1(); gen1.discard(gen2() ^ (counter += 0x9e3779b97f4a7c15ull)); gen2.discard(gen1());
			s[3] = gen1();

			// Very unlikely, but an all-zero state is not allowed for xoshiro256++.
			if (!(s[0] | s[1] | s[2] | s[3])) s[0] = 0x9e3779b97f4a7c15ull;

			return *this;
		}

		// Non-deterministic seed using hardware entropy. Delegates to the single-uint64_t
		// seed function for state initialization.
		MyT& seed() noexcept {
			return seed(Primitives::better_rand_device());
		}

		//-------------------------
		// Random number generation
		//-------------------------
		inline u64 operator()() noexcept {
			const u64 result = std::rotl(s[0] + s[3], 23) + s[0];
			const u64 t = s[1] << 17;

			s[2] ^= s[0];
			s[3] ^= s[1];
			s[1] ^= s[2];
			s[0] ^= s[3];

			s[2] ^= t;
			s[3] = std::rotl(s[3], 45);

			return result;
		}

		u64 draw64() { return operator()(); }
		u32 draw32() { return static_cast<u32>(operator()() >> 32); }

		inline double uni() noexcept {
			u64 j = (draw64() & 0x000FFFFFFFFFFFFFULL) | 0x3FF0000000000000ULL;
			return std::bit_cast<double>(j) - 1.0;
		}

		// Standard uniform distribution [0, limit)
		u64 uniform(u64 limit) noexcept {
			if (limit <= 1) return 0;
			u64 mask = (limit >= (1ULL << 63)) ? UINT64_MAX : (std::bit_ceil(limit) - 1);
			u64 x;
			do { x = operator()() & mask; } while (x >= limit);
			return x;
		}

		/**
		 * @brief Standard uniform distribution
		 * @param lo - unsigned integer: lower limit of the output range, inclusive.
		 * @param hi - unsigned integer: upper limit of the output range, inclusive.
		 * @return A uniformly distributed 64-bit value in the range [0, limit).
		 */
		u64 uniform(u64 lo, u64 hi) {
			if (lo > hi)
				std::swap(lo, hi);
			uint64_t range = hi - lo;
			if (range == UINT64_MAX)
				return draw64();
			else
				// we know range+1 won't overflow because of the previous if() check.
				return lo + uniform(range + 1);
		}

		//---------------
		// Jump functions 
		//---------------
		inline MyT& jump() noexcept {
			static const u64 JUMP[] = { 0x180ec6d33cfd0aba, 0xd5a61266f0c9392c, 0xa9582618e03fc9aa, 0x39abdc4529b1661c };
			u64 t[4] = { 0, 0, 0, 0 };
			for (int i = 0; i < 4; i++)
				for (int b = 0; b < 64; b++) {
					if (JUMP[i] & (UINT64_C(1) << b)) {
						t[0] ^= s[0]; t[1] ^= s[1]; t[2] ^= s[2]; t[3] ^= s[3];
					}
					operator()();
				}
			s[0] = t[0]; s[1] = t[1]; s[2] = t[2]; s[3] = t[3];
			return *this;
		}

		inline MyT& long_jump() noexcept {
			static const u64 LONG_JUMP[] = { 0x76e15d3efefdcbbf, 0xc5004e441c522fb3, 0x77710069854ee241, 0x39109bb02acbe635 };
			u64 t[4] = { 0, 0, 0, 0 };
			for (int i = 0; i < 4; i++)
				for (int b = 0; b < 64; b++) {
					if (LONG_JUMP[i] & (UINT64_C(1) << b)) {
						t[0] ^= s[0]; t[1] ^= s[1]; t[2] ^= s[2]; t[3] ^= s[3];
					}
					operator()();
				}
			s[0] = t[0]; s[1] = t[1]; s[2] = t[2]; s[3] = t[3];
			return *this;
		}

		// Multi-stream support
		static std::vector<MyT> factory(size_t n, u64 initial_seed) {
			std::vector<MyT> generators;
			generators.reserve(n);
			MyT base(initial_seed);
			for (size_t i = 0; i < n; ++i) {
				generators.emplace_back(base);
				base.long_jump();
			}
			return generators;
		}

		static inline u64 min() noexcept { return 0; }
		static inline u64 max() noexcept { return UINT64_MAX; }
	};
}
