#pragma once
// file common.h
// Common types and utilities shared across the library

#define NOMINMAX
#include <algorithm> // Needed for std::min
#include <array>
#include <bit>       // std::rotl, std::endian
#include <cstddef>   // std::byte
#include <cstdint>   // uint8_t
#include <cstring>   // memcpy
#include <iostream>
#include <limits>    // std::numeric_limits
#include <random>
#include <span>      // std::span
#include <stdexcept>
#include <string>
#include <type_traits> // Required for std::is_trivially_copyable_v
#include <utility>   // for std::swap
#include <vector>

#include "Block.h"              // crypto::Block<N>
#include "RNG_platform.h"       // get_entropy

// Platform requirements
static_assert(sizeof(std::byte) == 1, "std::byte must be 8 bits");
static_assert(std::endian::native == std::endian::little,
    "RNG library requires little-endian byte order");

#if !defined(_MSC_VER) && !defined(__SIZEOF_INT128__)
#error "Compiler must support 128-bit integers for wide multiplication"
#endif
#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace RNG {

    using u8 = std::uint8_t;
    using u16 = std::uint16_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;

    using Block32 = crypto::Block32;
    using Block64 = crypto::Block64;

    class Deterministic {};
    class NonDeterministic {};

    // 64×64 → 128-bit multiplication
    inline u64 umul128(u64 a, u64 b, u64* hi) noexcept
    {
#if defined(_MSC_VER)
        return _umul128(a, b, hi);
#else
        unsigned __int128 prod = static_cast<unsigned __int128>(a) * b;
        *hi = static_cast<u64>(prod >> 64);
        return static_cast<u64>(prod);
#endif
    }

    struct u128 {
        u64 lo;
        u64 hi;
    };

    inline u128 mul(u64 a, u64 b) noexcept
    {
        u128 res;
        res.lo = umul128(a, b, &res.hi);
        return res;
    }

} // namespace RNG
