#pragma once
#include "RNG_primitives.h"

namespace RNG {
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
			: state(Primitives::better_rand_device()) {
		}
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

			return Primitives::mix_fold_protected_modified(state, statexor);
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
}
