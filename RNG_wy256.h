#pragma once
/*
wy256 - a high-performance, 256-bit state PRNG based on the wyhash/wyrand philosophy.

Non-cryptographic: do not use for applications requiring cryptographic security.


Copyright 2026 Jim Staley

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

#include "RNG_primitives.h"
#include "RNG_SplitMix64.h"

namespace RNG {
	/**
	 * @class wy256
	 * @brief A high-performance, 256-bit state PRNG based on the wyhash/wyrand philosophy.
	 *
	 * wy256 provides a balance between the extreme speed of 64-bit LCGs and the
	 * statistical robustness of larger generators like mt19937. It features a
	 * period of 2^256 and supports O(1) jump operations for multi-threaded streams.
	 */

	class wy256 {
		/*
		PractRand Test Results

		Testing wy256with seed 9876543210, 128 GB
		Size: 128 GB
		Words: 17179869184

		Executing PractRand command: type test.bin | RNG_test.exe stdin64 -tf 2 -te 1 -tlmax 128GB -multithreaded
		RNG_test using PractRand version 0.94
		RNG = RNG_stdin64, seed = unknown
		test set = expanded, folding = extra

		length= 32 megabytes (2^25 bytes), time= 2.0 seconds		  no anomalies in 937 test result(s)
		length= 64 megabytes (2^26 bytes), time= 6.2 seconds		  no anomalies in 1008 test result(s)
		length= 128 megabytes (2^27 bytes), time= 11.2 seconds		  no anomalies in 1081 test result(s)
		length= 256 megabytes (2^28 bytes), time= 18.1 seconds		  no anomalies in 1151 test result(s)
		length= 512 megabytes (2^29 bytes), time= 28.9 seconds		  no anomalies in 1220 test result(s)
		length= 1 gigabyte (2^30 bytes), time= 48.5 seconds		      no anomalies in 1294 test result(s)
		length= 2 gigabytes (2^31 bytes), time= 84.9 seconds		  no anomalies in 1366 test result(s)
		length= 4 gigabytes (2^32 bytes), time= 155 seconds			  no anomalies in 1446 test result(s)
		length= 8 gigabytes (2^33 bytes), time= 300 seconds			  no anomalies in 1533 test result(s)
		length= 16 gigabytes (2^34 bytes), time= 593 seconds		  no anomalies in 1633 test result(s)
		length= 32 gigabytes (2^35 bytes), time= 1138 seconds		  no anomalies in 1715 test result(s)
		length= 64 gigabytes (2^36 bytes), time= 2277 seconds		  no anomalies in 1807 test result(s)
		length= 128 gigabytes (2^37 bytes), time= 4502 seconds		  no anomalies in 1902 test result(s)

		PractRand command completed successfully
		*/

		using MyT = wy256;

		/** @brief 256-bit Weyl increment limbs derived from the Golden Ratio. */
		static constexpr uint64_t INCR[] = {
			0x9e3779b97f4a7c15ull, 0xf39cc0605cedc834ull,
			0x1082276bf3a27251ull, 0xf86c6a11d0c18e95ull
		};

		/** @brief XOR-mixing constants used in the output stage to improve diffusion. Derived from the Golden Ratio */
		static constexpr uint64_t XORMIX[] = {
			0x2767f0b153d27b7full, 0x0347045b5bf1827full,
			0x01886f0928403002ull, 0xc1d64ba40f335e36ull
		};

		/** @brief Internal state represented as four 64-bit unsigned integers. */
		uint64_t state[4];

	public:
		using result_type = uint64_t;
		static constexpr uint64_t min() { return 0; }
		static constexpr uint64_t max() { return UINT64_MAX; }

		///////////////////////////
		// Construction and Seeding
		///////////////////////////

		/**
		 * @brief Constructs and seeds the generator using the hardware entropy anchor.
		 */
		wy256() noexcept { seed(); }

		/**
		 * @brief Constructs the generator with one or two 64-bit seed values.
		 * @param seed_val1 Primary seed value.
		 * @param seed_val2 Secondary seed value (optional, recommended for uniqueness).
		 */
		wy256(uint64_t seed_val1, uint64_t seed_val2 = 0) noexcept {
			seed(seed_val1, seed_val2);
		}

		/**
		 * @brief Re-seeds the generator using the hardware entropy anchor.
		 * @return Reference to this generator instance.
		 */
		MyT& seed() noexcept {
			return seed(Primitives::better_rand_device());
		}

		/**
		 * @brief Re-seeds the generator with specific 64-bit values.
		 * @param seed_val1 Primary seed.
		 * @return Reference to this generator instance.
		 */
		constexpr MyT& seed(u64 seed_val) noexcept {
			return seed(seed_val, 0xf39cc0605cedc834ull);
		}

		/**
		 * @brief Re-seeds the generator using 2 64-bit seed values.
		 * @param seed_val1 Primary seed.
		 * @param seed_val2 Secondary seed.
		 * @return Reference to this generator instance.
		 */
		constexpr MyT& seed(u64 seed_val1, u64 seed_val2) noexcept {
			SplitMix64 gen1(Primitives::pelican(seed_val1));
			SplitMix64 gen2(Primitives::pelican(seed_val2));

			uint64_t counter = 0xa2e834c5893a39ebull; // bits 64-127 of the golden ratio
			state[0] = gen1(); gen1.discard(gen2() ^ (counter += 0x9e3779b97f4a7c15ull)); gen2.discard(gen1());
			state[1] = gen1(); gen1.discard(gen2() ^ (counter += 0x9e3779b97f4a7c15ull)); gen2.discard(gen1());
			state[2] = gen1(); gen1.discard(gen2() ^ (counter += 0x9e3779b97f4a7c15ull)); gen2.discard(gen1());
			state[3] = gen1();

			// Note: An all-zero state is very unlikely, but not unacceptable for this generator, so we do not
			// need to guard against it. It is not known if there are any combinations of seed_val1 and seed_val2
			// that would produce an all-zero state.

			return *this;
		}

		///////////////////////////
		// Random Number Generation
		///////////////////////////

		/**
		 * @brief Generates a random 64-bit unsigned integer and advances the state.
		 * @return A uniformly distributed 64-bit value.
		 */
		inline uint64_t operator()() noexcept {
			increment();

			// Quality note: This could be upgraded to the mix_fold_protected variant for better diffusion
			// if PractRand testing reveals a weakness in the output. We have already successfully
			// passed 128 GB, but testing in the multiple TB range may reveal some weaknesses in the current
			// mixing approach.
			return Primitives::mix_fold(
				(state[0] + XORMIX[0]) ^ (state[3] + XORMIX[3]),
				(state[1] + XORMIX[1]) ^ (state[2] + XORMIX[2])
			);
		}

		/**
		 * @brief Generates a double-precision float in the range [0.0, 1.0).
		 * @note Uses IEEE 754 bit manipulation for maximum performance.
		 * @return A random double in [0.0, 1.0).
		 */
		inline double uni() noexcept {
			u64 j = (draw64() & 0x000FFFFFFFFFFFFFULL) | 0x3FF0000000000000ULL;
			return std::bit_cast<double>(j) - 1.0;
		}


		/**
		 * @brief 64 random bits.
		 * @return A uniformly distributed 64-bit value.
		 */
		u64 draw64() { return operator()(); }

		/**
		 * @brief 32 random bits.
		 * @return A uniformly distributed 32-bit value.
		 */
		u32 draw32() { return static_cast<u32>(operator()() >> 32); }


		// 
		/**
		 * @brief Standard uniform distribution
		 * @param limit - unsigned integer describing the upper limit of the output range.
		 * @return A uniformly distributed 64-bit value in the range [0, limit).
		 */
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

		/////////////////
		// Jump functions
		/////////////////

		inline wy256& discard(uint64_t nsteps)noexcept {
			if (nsteps == 0)return *this;

			uint64_t lo, hi;
			lo = Primitives::mul128(nsteps, INCR[0], hi);
			unsigned char c = 0;
			c = Primitives::add_carry(c, state[0], lo, &state[0]);
			c = Primitives::add_carry(c, state[1], hi, &state[1]);
			c = Primitives::add_carry(c, state[2], 0, &state[2]);
			c = Primitives::add_carry(c, state[3], 0, &state[3]);

			lo = Primitives::mul128(nsteps, INCR[1], hi);
			c = 0;
			c = Primitives::add_carry(c, state[1], lo, &state[1]);
			c = Primitives::add_carry(c, state[2], hi, &state[2]);
			c = Primitives::add_carry(c, state[3], 0, &state[3]);

			lo = Primitives::mul128(nsteps, INCR[2], hi);
			c = 0;
			c = Primitives::add_carry(c, state[2], lo, &state[2]);
			c = Primitives::add_carry(c, state[3], hi, &state[3]);

			lo = Primitives::mul128(nsteps, INCR[3], hi);
			c = 0;
			c = Primitives::add_carry(c, state[3], lo, &state[3]);
			// hi not inserted into state since it would be beyond 256 bits

			return *this;
		}

		/**
		 * @brief Advances the state by 2^128 steps in O(1) time.
		 * @return Reference to this generator instance.
		 */
		inline wy256& jump() noexcept {
			// Since 2^128*INCR is effectively INCR shifted left by 128 bits, we only need
			// to add the lower two limbs of INCR to the upper two limbs of state, with
			// carry propagation. The lower two limbs of state are unaffected by this jump.
			unsigned char c = 0;
			c = Primitives::add_carry(c, state[2], INCR[0], &state[2]);
			c = Primitives::add_carry(c, state[3], INCR[1], &state[3]);
			return *this;
		}

		/**
		 * @brief Advances the state by 2^192 steps in O(1) time.
		 * @return Reference to this generator instance.
		 */
		inline wy256& long_jump() noexcept {
			// Since 2^192*INCR is effectively INCR shifted left by 192 bits, we only need
			// to add the lower limb of INCR to the upper limb of state, and no carry propagation
			// is needed because any carry would exceed bit position 255. The lower three limbs of 
			// state are unaffected by this jump.
			state[3] += INCR[0];
			return *this;
		}

		///////////////////////
		// Multi-stream Support 
		///////////////////////

		/**
		 * @brief Creates a vector of independent wy256 generators.
		 * @details Each generator is separated by 2^192 steps to ensure no overlap
		 * in parallel streams.
		 * @param n Number of generators to create.
		 * @param initial_seed The common seed to base all streams on.
		 * @return std::vector containing n independent generators.
		 */
		static std::vector<wy256> factory(size_t n, uint64_t initial_seed) {
			std::vector<wy256> generators;
			generators.reserve(n);
			wy256 base(initial_seed);
			for (size_t i = 0; i < n; ++i) {
				generators.emplace_back(base);
				base.long_jump();
			}
			return generators;
		}


	private:
		/** @brief Internal 256-bit addition with carry propagation. */
		inline void increment() noexcept {
			unsigned char c = 0;
			for (int i = 0; i < 4; ++i)
				c = Primitives::add_carry(c, state[i], INCR[i], (unsigned long long*) & state[i]);
		}
	};
}
