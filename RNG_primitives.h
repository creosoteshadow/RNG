#pragma once

// RNG Primitives and utilities

#include <array>
#include <atomic>
#include <bit>
#include <chrono>
#include <cstdint>
#if defined(_MSC_VER)
#   include <intrin.h>
#   include <immintrin.h> // For __rdtsc on x86
#   pragma intrinsic(_umul128)
#endif
#include <limits>
#include <random>
#include <vector>


namespace RNG {
	using u64 = uint64_t;
	using u32 = uint32_t;
	using u8 = uint8_t;

	namespace Primitives {
		// Portable 128-bit multiplication function, used in the rapid_mix folding step.
#if defined(_MSC_VER)
		[[nodiscard]] inline uint64_t mul128(uint64_t a, uint64_t b, uint64_t& hi) noexcept {
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

	// rapid_mix folding function
		[[nodiscard]] inline uint64_t mix_fold(uint64_t a, uint64_t b) noexcept {
			uint64_t hi;
			uint64_t lo = mul128(a, b, hi);
			return lo ^ hi;
		}
		// rapid_mix folding function, protected variant with extra state involvement
		[[nodiscard]] inline uint64_t mix_fold_protected(uint64_t a, uint64_t b) noexcept {
			uint64_t hi;
			uint64_t lo = mul128(a, b, hi);
			return lo ^ hi ^ a ^ b;
		}
		// rapid_mix folding function, modified protected variant
		// This variant is used when we wish to call the mixer with b=a^secret, to
		// ensure that the final fold does not collapse to a simple function of the secret value.
		[[nodiscard]] inline uint64_t mix_fold_protected_modified(uint64_t a, uint64_t b) noexcept {
			uint64_t hi;
			uint64_t lo = mul128(a, b, hi);
			return lo ^ hi ^ a;
		}

		// portable add_carry function
#if defined(_MSC_VER)
		[[nodiscard]] inline uint8_t add_carry(uint8_t c, uint64_t a, uint64_t b, uint64_t* out) noexcept {
			return _addcarryx_u64(c, a, b, out);
		}
#elif defined(__GNUC__) || defined(__clang__)
		inline uint8_t add_carry(uint8_t c, uint64_t a, uint64_t b, uint64_t* out) noexcept {
			unsigned long long res;
			// __builtin_addcb is specifically for 'add with carry'
			uint8_t carry_out = __builtin_addcll(a, b, c, &res);
			*out = static_cast<uint64_t>(res);
			return carry_out;
		}
#endif

		// John Maiga's mixing function
		// https://jonkagstrom.com/mx3/mx3_rev2.html
		// Note: mx3(0) = 0, so if you use this as a seed mixer, be sure to avoid zero seeds or add a non-zero constant
		// before mx3.
		[[nodiscard]] inline constexpr uint64_t mx3(uint64_t x) noexcept {
			x ^= x >> 32;
			x *= 0xbea225f9eb34556dULL;
			x ^= x >> 29;
			x *= 0xbea225f9eb34556dULL;
			x ^= x >> 32;
			x *= 0xbea225f9eb34556dULL;
			x ^= x >> 29;
			return x;
		}


		// Pelle Evensen's NASAM mixer
		// https://mostlymangling.blogspot.com/2020/01/nasam-not-another-strange-acronym-mixer.html
		// Note: nasam(0) = 0, so if you use this as a seed mixer, be sure to avoid zero seeds or add a non-zero constant
		// before nasam.
		inline constexpr uint64_t nasam(uint64_t x) noexcept {
			x ^= std::rotr(x, 25) ^ std::rotr(x, 47);
			x *= 0x9E6C63D0676A9A99ULL;
			x ^= x >> 23 ^ x >> 51;
			x *= 0x9E6D62D06F6A9A9BULL;
			x ^= x >> 23 ^ x >> 51;

			return x;
		}

		// Pelican mixing function
		// https://github.com/tommyettinger/sarong/blob/master/src/main/java/sarong/PelicanRNG.java
		inline constexpr uint64_t pelican(uint64_t state) noexcept {
			uint64_t z = state;

			// Using std::rotl for the rotation patterns
			z = (z ^ std::rotl(z, 41) ^ std::rotl(z, 17) ^ 0xD1B54A32D192ED03ULL) * 0xAEF17502108EF2D9ULL;

			// Xorshift steps
			z = (z ^ z >> 43 ^ z >> 31 ^ z >> 23) * 0xDB4F0B9175AE2165ULL;

			return (z ^ z >> 28);
		}


		[[nodiscard]] uint64_t better_rand_device() noexcept {
			// 1. High-resolution wall clock
			uint64_t now = static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());

			// 2. CPU Cycle counter with ARM/x86 portability
			uint64_t tsc;
#if defined(_MSC_VER) || defined(__i386__) || defined(__x86_64__)
			tsc = __rdtsc();
#else
			// Fallback for non-x86: use high_resolution_clock
			tsc = static_cast<uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count());
#endif

			// 3. Static components to reduce OS overhead
			static std::atomic<uint64_t> sequence{ 0x9E3779B97F4A7C15ULL }; // Start with a constant
			uint64_t seq = sequence.fetch_add(1, std::memory_order_relaxed);

			// 4. Hardware Entropy
			static std::random_device rd;
			uint64_t entropy = (static_cast<uint64_t>(rd()) << 32) | rd();

			// Final mix
			return pelican(now ^ tsc ^ seq ^ entropy);
		}
	} // namespace Primitives
} // namespace RNG
#pragma once
