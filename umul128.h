#pragma once

/*
 * Portable 64 × 64 → 128-bit unsigned integer multiplication.
 *
 * Provides minimal-overhead access to wide multiplication on supported platforms.
 * All functions are inline and live in namespace detail.
 *
 * - umul128(a, b, hi_out) → returns low 64 bits, stores high 64 bits via pointer
 * - mul(a, b)             → returns a u128 struct containing both parts
 */

#include <cstdint>  // std::uint64_t

 // Fail early if the compiler lacks support for fast 128-bit multiplication
#if !defined(_MSC_VER) && !defined(__SIZEOF_INT128__)
#error "Compiler/platform does not support fast 128-bit integer multiplication"
#endif

#if defined(_MSC_VER)
#include <intrin.h>  // _umul128 on x86-64
#endif

namespace RNG_detail {

    /// Performs 64-bit × 64-bit → 128-bit unsigned multiplication.
    /// Returns the low 64 bits; stores the high 64 bits in *hi.
    /// Zero-overhead wrapper — compiles to a single mul instruction.
    /// Supported on: MSVC (all x86-64 versions), GCC/Clang with __int128 (essentially all modern 64-bit targets)
   [[nodiscard]] inline std::uint64_t umul128(std::uint64_t a, std::uint64_t b, std::uint64_t* hi) noexcept
    {
#if defined(_MSC_VER)
        return _umul128(a, b, hi);
#elif defined(__SIZEOF_INT128__)
        unsigned __int128 product = static_cast<unsigned __int128>(a) * b;
        *hi = product >> 64;                  // implicit cast to uint64_t is fine and common
        return static_cast<std::uint64_t>(product);

#else
#error "Unsupported compiler/platform for RNG_detail::umul128"
#endif
    }

    /// Simple 128-bit unsigned integer representation.
    struct u128 {
        std::uint64_t lo;
        std::uint64_t hi;
    };

    /// Convenience wrapper returning both parts of the product as a struct.
    inline u128 mul(std::uint64_t a, std::uint64_t b) noexcept
    {
        u128 result;
        result.lo = umul128(a, b, &result.hi);
        return result;
    }

}  // namespace RNG_detail

