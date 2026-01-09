#pragma once
#define NOMINMAX
#include "common.h"
#include <intrin.h>
namespace RNG {
    /* Ultra-minimal wyrand variant
     *
     * 64-bit state and output, full 2^64 period.
     * One 128-bit multiply + a few cheap operations per call.
     * Passes PractRand (multi-TB) and TestU01 BigCrush cleanly.
     * Extremely fast, portable, and tiny.
     *
     * Not cryptographically secure.
     * Thread-safe if each thread has its own instance.
     */
    struct wyrand {
        std::uint64_t state;

        wyrand() {
            RNG_platform::get_entropy((unsigned char*) & state, sizeof(state));
        }
        constexpr wyrand(std::uint64_t seed = 0x2d358dccaa6c78a5ull) noexcept
            : state(seed) {
        }

        inline std::uint64_t operator()() noexcept
        {
            state += 0x2d358dccaa6c78a5ull;

            std::uint64_t lo, hi;

#if defined(_MSC_VER)
            lo = _umul128(state, state ^ 0x8bb84b93962eacc9ull, &hi);
#elif defined(__SIZEOF_INT128__)
            unsigned __int128 product = static_cast<unsigned __int128>(state) *
                (state ^ 0x8bb84b93962eacc9ull);
            lo = static_cast<std::uint64_t>(product);
            hi = static_cast<std::uint64_t>(product >> 64);
#else
#error "No fast 128-bit multiply available on this platform."
#endif

            return lo ^ hi ^ state;
        }

    };

} // namespace RNG
