#pragma once
// File: RNG_SplitMix64.h

#include "common.h"

namespace RNG {

    // -----------------------------------------------------------------
    // Very small, fast SplitMix64 (fully constexpr-friendly), except for 
    // the non-deterministic seeding constructor.
    // -----------------------------------------------------------------

    class SplitMix64 {
        // u64 is defined in RNG_detail.h, namespace RNG.
        static constexpr u64 INCREMENT = 0x9e3779b97f4a7c15ULL;
        static constexpr u64 MUL1 = 0xbf58476d1ce4e5b9ULL;
        static constexpr u64 MUL2 = 0x94d049bb133111ebULL;

        u64 state;
    public:
        using result_type = u64;

        // Cryptographically secure non-deterministic seeding, cannot be noexcept
        // Gets platform entropy from BCryptGenRandom on Wndows, or SYS_getrandom with a fallback to /dev/urandom on Linux

        // No arg constructor to indicate non-deterministic seeding
        SplitMix64() noexcept(false) {
            RNG_platform::get_entropy((unsigned char*)&state, sizeof(state));
        }

        // constructor tag to indicate non-deterministic seeding
        // NonDeterministic is defined in RNG_detail.h, namespace RNG.
        SplitMix64(NonDeterministic) noexcept(false) {
            RNG_platform::get_entropy((unsigned char*)&state, sizeof(state));
        }

        // Deterministic seeding constructors
        constexpr SplitMix64(u64 seed) noexcept : state(seed) {} // default = deterministic

        // Deterministic is defined in RNG_detail.h, namespace RNG.
        constexpr SplitMix64(Deterministic, u64 seed) noexcept : state(seed) {}
        constexpr u64 operator()() noexcept {
            u64 z = (state += INCREMENT);
            z = (z ^ (z >> 30)) * MUL1;
            z = (z ^ (z >> 27)) * MUL2;
            return z ^ (z >> 31);
        }

        constexpr SplitMix64& discard(u64 n) noexcept {
            state += INCREMENT * n;
            return *this;
        }

        static constexpr result_type min()  noexcept { return 0; }
        static constexpr result_type max()  noexcept { return UINT64_MAX; }
    };// class SplitMix64
}// namespace RNG
