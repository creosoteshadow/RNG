#pragma once

/*
This file contains a collection of non-cryptographic random number generators, each with different characteristics
and use cases. The implementations are designed to be efficient, high-quality, and suitable for a wide range of 
applications such as simulations, games, and randomized algorithms.

Security Warning: These generators are NOT designed for cryptographic use. 

Contents:
	uint64_t mx3(uint64_t x) - John Maiga's mixing function
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

#include <array>
#include <atomic>
#include <random>
#include <limits>
#include <cstdint>
#include <vector>
#include <bit>
#include <chrono>


#if defined(_MSC_VER)
#include <intrin.h>
#pragma intrinsic(_umul128)
#endif


namespace RNG {

	using u64 = uint64_t;
	using u32 = uint32_t;
	using u8 = uint8_t;

	// Portable 128-bit multiplication function, used in the rapid_mix foldint step.
#if defined(_MSC_VER)
	inline uint64_t mul128(uint64_t a, uint64_t b, uint64_t& hi) noexcept {
		return _umul128(a, b, &hi);
	}
#elif defined(__GNUC__) || defined(__clang__)
	inline uint64_t mul128(uint64_t a, uint64_t b, uint64_t& hi) noexcept {
		unsigned __int128 prod = (unsigned __int128)a * b;
		hi = static_cast<uint64_t>(prod >> 64);
		return static_cast<uint64_t>(prod);
	}
#else
#error "128-bit multiplication not supported on this compiler."
#endif

	// portable add_carry function
#if defined(_MSC_VER)
	inline uint8_t add_carry(uint8_t c, uint64_t a, uint64_t b, uint64_t* out) noexcept {
		return _addcarryx_u64(c, a, b, out);
	}
#elif defined(__GNUC__) || defined(__clang__)
	inline uint8_t add_carry(uint8_t c, uint64_t a, uint64_t b, uint64_t* out) noexcept {
		unsigned long long sum;
		uint8_t c1 = __builtin_add_overflow(a, b, &sum);
		uint8_t c2 = __builtin_add_overflow(sum, c, (unsigned long long*)out);
		return c1 | c2;
	}
#endif

	// John Maiga's mixing function
	static uint64_t mx3(uint64_t x) noexcept {
		x ^= x >> 32;
		x *= 0xbea225f9eb34556dULL;
		x ^= x >> 29;
		x *= 0xbea225f9eb34556dULL;
		x ^= x >> 32;
		x *= 0xbea225f9eb34556dULL;
		x ^= x >> 29;
		return x;
	}

	static uint64_t better_rand_device() {
		/*
		Adds a counter and a high-resolution timestamp to the random_device output, all mixed together with a strong mixer.
		The reason for this is that some versions of std::random_device, particularly on older platforms or certain 
		implementations, may have low entropy or even be deterministic. By combining it with a high-resolution clock and
		a counter, we ensure that we get a unique seed each time, even if the random_device is not providing good randomness.

		*** Security Warning *** Unless std::random_device is implemented with a secure hardware RNG, this function is not suitable
		for cryptographic use. However, it should be more than sufficient for seeding non-cryptographic PRNGS in most
		applications.

		Time Sensitivity: The clock and CPU cycle counter ensure that different program executions start at different points in 
		the state space.

		Unique Streams: The counter ensures that if you call this function multiple times within the same nanosecond, you
		still get different seeds.

		Entropy Anchor: The random_device provides the "true" randomness from the hardware (RDRAND/urandom) whenever it's
		available.
		*/

		// 1. High-resolution wall clock
		auto now = std::chrono::steady_clock::now().time_since_epoch().count();

		// 2. CPU Cycle counter (The Jitter Source)
		uint64_t tsc = __rdtsc();

		// 3. Atomic counter (The Thread-Safety Anchor)
		static std::atomic<uint64_t> sequence{ 0 };
		uint64_t seq = sequence.fetch_add(1, std::memory_order_relaxed);

		// 4. Hardware Entropy (The Random Anchor)
		std::random_device rd;
		uint64_t entropy = (static_cast<uint64_t>(rd()) << 32) | rd();

		// Fold them all together using the mx3 mixer
		return mx3(mx3(now) ^ mx3(tsc) ^ mx3(seq)) ^ entropy;
	}

	class SplitMix64
	{
		using MyT = SplitMix64;

		constexpr static u64 INCREMENT = 0x9e3779b97f4a7c15;
		constexpr static u64 MUL1 = 0xbf58476d1ce4e5b9;
		constexpr static u64 MUL2 = 0x94d049bb133111eb;
		u64 state;

	public:
		using result_type = u64;

		//--------------------------
		// Construct, destruct, seed
		//--------------------------
		constexpr SplitMix64(u64 seed)noexcept :state(seed) {} // explicit seed
		SplitMix64()noexcept
			: state(better_rand_device()) {
		}
		SplitMix64(const SplitMix64& other) : state(other.state) {};
		SplitMix64(SplitMix64&& other) : state(other.state) {}
		//~SplitMix64() = default;

		//-------------------------
		// Random number generation
		//-------------------------

		u64 operator()() noexcept {
			state += INCREMENT;
			u64 z = state;
			z = (z ^ (z >> 30)) * MUL1;
			z = (z ^ (z >> 27)) * MUL2;
			return z ^ (z >> 31);
		}

		// Return 64 random bits
		u64 draw64() {
			return operator()();
		}

		// return 32 random bits
		uint32_t draw32() {
			return static_cast<uint32_t>(operator()() >> 32);
		}

		// Return a uniformly distributed double in the range [0.0, 1.0)
		inline double uni() noexcept {
			// 1. Get a full 64 bits regardless of the underlying engine size
			u64 j = this->draw64();

			// 2. Clear the top 12 bits to leave room for the sign/exponent
			// This leaves 52 bits of random mantissa.
			j &= 0x000FFFFFFFFFFFFFULL;

			// 3. Set the exponent to 1023 (which represents 2^0 = 1)
			// The resulting double bit pattern will be in the range [1.0, 2.0)
			j |= 0x3FF0000000000000ULL;

			// 4. Reinterpret the bits as a double
			// bit_cast is safer and often faster than memcpy for this
			double d = std::bit_cast<double>(j);

			// 5. Subtract 1.0 to shift the range from [1.0, 2.0) to [0.0, 1.0)
			return d - 1.0;
		}

		// Return in range [0,limit)
		u64 uniform(u64 limit) noexcept {
			if (limit <= 1) return 0;

			u64 mask = (limit >= (1ULL << 63)) ? UINT64_MAX : (std::bit_ceil(limit) - 1);
			u64 x;
			do {
				x = (*this)() & mask;
			} while (x >= limit);
			return x;
		}

		// Return in range [lo,hi]
		u64 uniform(u64 lo, u64 hi) {
			if (lo == 0 && hi == UINT64_MAX) return draw64();
			return lo + uniform(hi - lo + 1);
		}

		//---------------
		// Jump functions 
		//---------------

		constexpr inline SplitMix64& discard(u64 nsteps)noexcept {
			state += nsteps * INCREMENT;
			return *this;
		}

		// jump, 2^32 steps
		constexpr inline SplitMix64& jump()noexcept {
			state += (INCREMENT << 32);
			return *this;
		}

		// long_jump, 2^48 steps
		constexpr inline SplitMix64& long_jump()noexcept {
			state += (INCREMENT << 48);
			return *this;
		}

		constexpr inline SplitMix64& reseed(u64 seed)noexcept {
			state = seed;
			return *this;
		}


		//---------------------
		// Multi-stream support
		//---------------------
		static std::vector<SplitMix64> factory(size_t n, u64 initial_seed) {
			// Returns a vector of n independent SplitMix64 generators, each initialized with the
			// same seed but separated by 2^48 steps using long_jump(). This allows for up to 2^16 
			// independent streams with a 2^48 step separation, which is a safe distance for most 
			// applications. For more extreme separation, consider using wy128 or wy256 with their 
			// 'big_jump' methods.
			std::vector<SplitMix64>generators;
			generators.reserve(n);
			SplitMix64 base(initial_seed);
			for (size_t i = 0; i < n; ++i) {
				generators.emplace_back(base);
				base.long_jump();
			}
			return generators;
		}

		//---------------
		// min and max
		//---------------

		static inline u64 min() noexcept {
			return 0;
		}
		static inline u64 max() noexcept {
			return std::numeric_limits<result_type>::max();
		}

	};

	class wyrand {
		/*
		* wyrand - a fast 64 bit non-cryptographic random number generator by Wang Yi.
		* 
		* This class is a direct implementation of the original wyrand algorithm, with a slight modification to
		* the mixing function to improve the diffusion of the state in the specific feed pattern used here. The
		* original wyrand is the basis for both wyhash and rapidhash, and has been shown to pass PractRand testing
		* up to 4 TB with no failures. This implementation retains the core characteristics of wyrand.
		* 
		* Original Source code, simplified from https://github.com/Nicoshev/rapidhash/blob/master/rapidhash.h
		* and https://github.com/Nicoshev/rapidhash/blob/master/secret.h .
		* (Simplified to include only the MSVC compatible version of the mixing function, and demonstrating the
		* difference between the protected and unprotected variants of the mixer.)
		*
		*	  #define RAPIDHASH_PROTECTED
		*	  constexpr inline u64 rapid_mix(u64 A, u64 B) noexcept
		*	  {
		*	  	  u64 lo, hi;
		*	  	  lo = _umul128(A, B, &hi);
		*	  #ifdef RAPIDHASH_PROTECTED
		*	  	  return A ^ B ^ (lo ^ hi);
		*	  #else
		*	  	  return A ^ B;
		*	  #endif
		*	  }
		*
		*	  //The wyrand PRNG that pass BigCrush and PractRand
		*	  static inline u64 wyrand(u64* seed) {
		*	  	  *seed += 0x2d358dccaa6c78a5ull;
		*	  	  return rapid_mix(*seed, *seed ^ 0x8bb84b93962eacc9ull);
		*	  }
		*/
		using MyT = wyrand;
		static constexpr u64 INCREMENT = 0x2d358dccaa6c78a5ull; // constant from rapidhash website, derived from golden ratio
		static constexpr u64 XORMIX = 0x8bb84b93962eacc9ull; // constant from rapidhash website
		u64 state;

		constexpr static bool PROTECTED_MODE = false; // Set to true to include the state in the output mixer, 
		// which provides better statistical quality at the cost 
		// of some performance.
	public:
		using result_type = u64;

		//--------------------------
		// Construct, destruct, seed
		//--------------------------
		constexpr wyrand(u64 seed)noexcept :state(seed) {} // explicit seed
		wyrand()noexcept  // non-deterministic constructor
			: state(better_rand_device()) {}
		wyrand(const wyrand& other) = default;
		wyrand(wyrand&& other) = default;
		~wyrand() = default;

		wyrand& seed(u64 seedval)noexcept {
			state = seedval;
			return *this;
		}

		//-------------------------
		// Random number generation
		//-------------------------

		inline u64 operator()() noexcept {
			state += INCREMENT;
			const u64 statexor = state ^ XORMIX;
			u64 lo, hi;

#ifdef _MSC_VER
			lo = mul128(state, statexor, hi);
#else
			uint128_t product = uint128_t(state) * statexor;
			lo = static_cast<u64>(product);
			hi = static_cast<u64>(product >> 64);
#endif

			if constexpr (PROTECTED_MODE) {
				return (lo ^ hi) ^ statexor;
			}
			else {
				return (lo ^ hi);
			}
		}

		// Return 64 random bits
		u64 draw64() {
			return operator()();
		}

		// return 32 random bits
		uint32_t draw32() {
			return static_cast<uint32_t>(operator()() >> 32);
		}

		// Return a uniformly distributed double in the range [0.0, 1.0)
		inline double uni() noexcept {
			// 1. Get a full 64 bits regardless of the underlying engine size
			u64 j = this->draw64();

			// 2. Clear the top 12 bits to leave room for the sign/exponent
			// This leaves 52 bits of random mantissa.
			j &= 0x000FFFFFFFFFFFFFULL;

			// 3. Set the exponent to 1023 (which represents 2^0 = 1)
			// The resulting double bit pattern will be in the range [1.0, 2.0)
			j |= 0x3FF0000000000000ULL;

			// 4. Reinterpret the bits as a double
			// bit_cast is safer and often faster than memcpy for this
			double d = std::bit_cast<double>(j);

			// 5. Subtract 1.0 to shift the range from [1.0, 2.0) to [0.0, 1.0)
			return d - 1.0;
		}

		// Return in range [0,limit)
		u64 uniform(u64 limit) noexcept {
			if (limit <= 1) return 0;

			u64 mask = (limit >= (1ULL << 63)) ? UINT64_MAX : (std::bit_ceil(limit) - 1);
			u64 x;
			do {
				x = (*this)() & mask;
			} while (x >= limit);
			return x;
		}

		// Return in range [lo,hi]
		u64 uniform(u64 lo, u64 hi) {
			if (lo == 0 && hi == UINT64_MAX) return draw64();
			return lo + uniform(hi - lo + 1);
		}

		//---------------
		// Jump functions 
		//---------------

		constexpr inline MyT& discard(u64 nsteps)noexcept {
			state += nsteps * INCREMENT;
			return *this;
		}

		// jump, 2^32 steps
		constexpr inline MyT& jump()noexcept {
			state += (INCREMENT << 32);
			return *this;
		}

		// long_jump, 2^48 steps
		constexpr inline MyT& long_jump()noexcept {
			state += (INCREMENT << 48);
			return *this;
		}

		constexpr inline MyT& reseed(u64 seed)noexcept {
			state = seed; 
			return *this;
		}

		
		//---------------------
		// Multi-stream support
		//---------------------
		static std::vector<MyT> factory(size_t n, u64 initial_seed) {
			// Returns a vector of n independent generators, each initialized with the
			// same seed but separated by 2^48 steps using long_jump(). This allows for up to 2^16 
			// independent streams with a 2^48 step separation, which is a safe distance for most 
			// applications. For more extreme separation, consider using wy256 with their 
			// 'big_jump' methods.
			std::vector<MyT >generators;
			generators.reserve(n);
			MyT base(initial_seed);
			for (size_t i = 0; i < n; ++i) {
				generators.emplace_back(base);
				base.long_jump();
			}
			return generators;
		}

		//---------------
		// min and max
		//---------------

		static inline u64 min() noexcept {
			return 0;
		}
		static inline u64 max() noexcept {
			return std::numeric_limits<result_type>::max();
		}
	};

	class wy256 {
		/*
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
		// 256 bit state, 64 bit output, period 2^256
		// jump, 2^128
		// long_jump, 2^192

		// 256-bit Weyl increment: four 64-bit limbs, each odd and derived from golden-ratio constants
		// Source: https://www.numberworld.org/constants.html
		// A high-quality, full-rank, well-diffused increment is essential for the lightweight
		// rapid_mix fold to produce statistically excellent output in this wide additive design.
		static constexpr u64 INCR[] = {
			0x9e3779b97f4a7c15ull,
			0xf39cc0605cedc834ull,
			0x1082276bf3a27251ull,
			0xf86c6a11d0c18e95ull
		};

		// XORMIX constants: also selected from the same golden-ratio source
		static constexpr u64 XORMIX[] = { 
			0x2767f0b153d27b7full, 
			0x0347045b5bf1827full, 
			0x01886f0928403002ull, 
			0xc1d64ba40f335e36ull };

		// 256 bit state
		u64 state[4];

	public:
		using result_type = u64;

		//--------------------------
		// Construct, destruct, seed
		//--------------------------
		wy256(uint64_t seed_val1, uint64_t seed_val2 = 0) noexcept
		{
			seed(seed_val1, seed_val2);
		}

		wy256()noexcept { // non-deterministic constructor
			seed();
		}

		wy256(const wy256& other) = default;
		wy256(wy256&& other) = default;
		~wy256() = default;

		// Seed from one or two 64 bit values. The second value is optional, but recommended.
		MyT& seed(u64 seed_val1, u64 seed_val2 = 0)
		{
			auto gen = SplitMix64(mx3(seed_val1 + INCR[0]));
			gen.discard(gen() ^ mx3(seed_val2 + INCR[1]));

			state[0] = gen();
			state[1] = gen();
			state[2] = gen();
			state[3] = gen();

			return *this;
		}
		MyT& seed() {
			u64 seedval = better_rand_device();
			auto gen = SplitMix64(seedval);

			state[0] = gen();
			state[1] = gen();
			state[2] = gen();
			state[3] = gen();

			return *this;
		}

		//-------------------------
		// Random number generation
		//-------------------------

		// Return random value
		inline u64 operator()()noexcept {
			increment();

			return rapid_mix(
				(state[0] + XORMIX[0]) ^ (state[3] + XORMIX[3]),
				(state[1] + XORMIX[1]) ^ (state[2] + XORMIX[2])
			);
		}

		// Return 64 random bits
		u64 draw64() {
			return operator()();
		}

		// return 32 random bits
		uint32_t draw32() {
			return static_cast<uint32_t>(operator()() >> 32);
		}

		// Return a uniformly distributed double in the range [0.0, 1.0)
		inline double uni() noexcept {
			// 1. Get a full 64 bits regardless of the underlying engine size
			u64 j = this->draw64();

			// 2. Clear the top 12 bits to leave room for the sign/exponent
			// This leaves 52 bits of random mantissa.
			j &= 0x000FFFFFFFFFFFFFULL;

			// 3. Set the exponent to 1023 (which represents 2^0 = 1)
			// The resulting double bit pattern will be in the range [1.0, 2.0)
			j |= 0x3FF0000000000000ULL;

			// 4. Reinterpret the bits as a double
			// bit_cast is safer and often faster than memcpy for this
			double d = std::bit_cast<double>(j);

			// 5. Subtract 1.0 to shift the range from [1.0, 2.0) to [0.0, 1.0)
			return d - 1.0;
		}

		// Return in range [0,limit)
		u64 uniform(u64 limit) noexcept {
			if (limit <= 1) return 0;

			u64 mask = (limit >= (1ULL << 63)) ? UINT64_MAX : (std::bit_ceil(limit) - 1);
			u64 x;
			do {
				x = (*this)() & mask;
			} while (x >= limit);
			return x;
		}

		// Return in range [lo,hi]
		u64 uniform(u64 lo, u64 hi) {
			if (lo == 0 && hi == UINT64_MAX) return draw64();
			return lo + uniform(hi - lo + 1);
		}

		//---------------
		// Jump functions 
		//---------------

		// discard(nsteps) is equivalent to calling operator() nsteps times, but is much faster
		MyT& discard(uint64_t nsteps) noexcept {
			if (nsteps == 0) return *this;

			for (int j = 0; j < 4; ++j) {
				u64 lo, hi;
				lo = mul128(INCR[j], nsteps, hi);
				addcarry_branched(state, j, lo);
				if (j + 1 < 4)
					addcarry_branched(state, j + 1, hi);
			}

			return *this;
		}

		// Discard an arbitrary 256 bit number of steps.
		// Note: jump and long_jump are faster ways to make very large jumps, so only use this
		// when an arbitrary large step is needed.
		MyT& discard(const std::array<u64, 4>& nsteps) noexcept {
			// product = (nsteps * INCR) mod (2^256)
			std::array<u64, 4>product = { 0 };
			for (int i = 0; i < 4; ++i) {
				for (int j = 0; j < 4; ++j) {
					u64 lo, hi;
					if (i + j < 4) { // don't need higher order terms - exceeds 2^256-1
						lo = mul128(INCR[i], nsteps[j], hi);
						// We know the low 64 bits is needed because we are inside the if() conditional.
						addcarry_branched(product.data(), i + j, lo);
						if (i + j + 1 < 4)
							// If the high 64 bits exceed2 2^256-1 we don't need to add it
							addcarry_branched(product.data(), i + j + 1, hi);
					}
				}
			}

			// state += product
			unsigned char c = 0;
			c = add_carry(c, state[0], product[0], &state[0]);
			c = add_carry(c, state[1], product[1], &state[1]);
			c = add_carry(c, state[2], product[2], &state[2]);
			c = add_carry(c, state[3], product[3], &state[3]);

			return *this;
		}

		// big_jump is equivalent to calling operator() 2^128 times
		inline MyT& jump() noexcept {
			unsigned char c = 0;
			// We start adding at state[1] because INCR is shifted left 64 bits
			c = _addcarryx_u64(c, state[1], INCR[0], &state[1]);
			c = _addcarryx_u64(c, state[2], INCR[1], &state[2]);
			c = _addcarryx_u64(c, state[3], INCR[2], &state[3]);
			return *this;
		}

		// long_jump is equivalent to calling operator() 2^192 times
		inline MyT& long_jump() {
			unsigned char c = 0;
			// We start adding at state[3] because INCR is shifted left 192 bits
			c = _addcarryx_u64(c, state[3], INCR[0], &state[3]);
			return *this;
		}
		
		//---------------------
		// Multi-stream support
		//---------------------
		static std::vector<MyT> factory(size_t n, u64 initial_seed) {
			// Returns a vector of n independent wyrand generators, each initialized with the
			// same seed but separated by 2^192 steps using long_jump(). This allows for up to 2^64 
			// independent streams with a 2^192 step separation, which is a safe distance for any
			// conceivable application.
			std::vector<MyT>generators;
			generators.reserve(n);
			MyT base(initial_seed);
			for (size_t i = 0; i < n; ++i) {
				generators.emplace_back(base);
				base.long_jump();
			}
			return generators;
		}

		//---------------
		// min and max
		//---------------

		static inline u64 min() noexcept {
			return 0;
		}
		static inline u64 max() noexcept {
			return std::numeric_limits<result_type>::max();
		}

	// Private helper functions
	private:
		// Move the state one increment forward
		inline unsigned char increment() noexcept {
			// state += INCR
			unsigned char c = 0;
			c = add_carry(c, state[0], INCR[0], &state[0]);
			c = add_carry(c, state[1], INCR[1], &state[1]);
			c = add_carry(c, state[2], INCR[2], &state[2]);
			c = add_carry(c, state[3], INCR[3], &state[3]);
			return c;
		}

		// Fast folding mix (from rapidhash).
		static inline uint64_t rapid_mix(uint64_t A, uint64_t B) noexcept {
			uint64_t hi, lo = mul128(A, B, hi);  // reuse B for hi
			return (A ^ B) ^ (lo ^ hi); // protected variant, somewhat higher quality
			//return lo ^ hi; // fastest, unprotected variant
		}


		/**
		 * Add a value to an arbitrary branch in a 4-branch array, and propagate carry bits upward.
		 *
		 * Performs: x += (value << (64 * branch)) with 256-bit carry propagation.
		 *
		 * Logic: Entering at 'branch' adds the initial value to that limb.
		 * By then setting value = 0, the subsequent fallthrough cases effectively
		 * become: c_out = x[n] + 0 + c_in.
		 * This ripples the carry bit through the higher-order limbs until it is
		 * absorbed or the state ends.
		 *
		 * Arguments:
		 *		x      ... pointer, valid for range x[0...3]
		 *		branch ... index into x
		 *		value  ... value to be added to x[branch]
		 */
		static inline void addcarry_branched(u64* x, int branch, u64 value) noexcept {
			unsigned char c = 0;

			switch (branch) {
			case 0: c = add_carry(c, x[0], value, &x[0]); value = 0; [[fallthrough]];
			case 1: c = add_carry(c, x[1], value, &x[1]); value = 0; [[fallthrough]];
			case 2: c = add_carry(c, x[2], value, &x[2]); value = 0; [[fallthrough]];
			case 3: c = add_carry(c, x[3], value, &x[3]);
				break;
			}
		}

		// Helper function -- Overload the more general addcarry(u64*, int, u64).
		// Called from discard().
		// Delegates to the static addcarry function.
		inline void addcarry_branched(int branch, u64 value) noexcept {
			addcarry_branched(state, branch, value);
		}

	};


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

		static inline u64 rotl(const u64 x, int k) noexcept {
			return (x << k) | (x >> (64 - k));
		}

	public:
		using result_type = u64;

		//--------------------------
		// Construct, destruct, seed
		//--------------------------
		xoshiro256plusplus(u64 seed_val) noexcept { seed(seed_val); }
		xoshiro256plusplus() noexcept { seed(); }

		MyT& seed(u64 seed_val) noexcept {
			// Filling the 256-bit state using SplitMix64 (as recommended by authors)
			SplitMix64 filler(seed_val);
			s[0] = filler();
			s[1] = filler();
			s[2] = filler();
			s[3] = filler();
			return *this;
		}

		MyT& seed() noexcept {
			return seed(better_rand_device());
		}

		//-------------------------
		// Random number generation
		//-------------------------
		inline u64 operator()() noexcept {
			const u64 result = rotl(s[0] + s[3], 23) + s[0];
			const u64 t = s[1] << 17;

			s[2] ^= s[0];
			s[3] ^= s[1];
			s[1] ^= s[2];
			s[0] ^= s[3];

			s[2] ^= t;
			s[3] = rotl(s[3], 45);

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
