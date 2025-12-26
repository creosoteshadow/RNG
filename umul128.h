#pragma once
// file umul128.h. Handles 128 bit multiply.

// Defines a cross-platform version of the following:
//  _umul128 ... Portable version of Microsoft intrinsic _umul128. Works with both MSVC and Unix-like systems.
//  mul128 ... Returns 128-bit product of two 64-bit unsigned integers.
//  uint128_t ... Defines a simple 128-bit value.
//  lo128 ... Returns the low 64 bits of a 128-bit value.
//  hi128 ... Returns the high 64 bits of a 128-bit value.
#include <cstdint>
#if defined(_MSC_VER)
    #include <intrin.h>
#endif

//
// Define 128-bit unsigned struct, as well as lo and hi extractors
//
struct uint128_t {
    std::uint64_t lo;
    std::uint64_t hi;
    constexpr uint128_t(std::uint64_t l = 0, std::uint64_t h = 0) : lo(l), hi(h) {}
};
inline constexpr std::uint64_t lo128(uint128_t x) { return x.lo; }
inline constexpr std::uint64_t hi128(uint128_t x) { return x.hi; }

// Define mul128, the 128-bit product of two 64-bit unsigned values.
#if defined(_MSC_VER)
    inline uint128_t mul128(std::uint64_t a, std::uint64_t b) {
        a = _umul128(a, b, &b);
        return { a, b };
    }
#elif defined(__SIZEOF_INT128__)
    inline uint128_t mul128(std::uint64_t a, std::uint64_t b) {
        __uint128_t product = static_cast<__uint128_t>(a) * static_cast<__uint128_t>(b);
        std::uint64_t lo = static_cast<std::uint64_t>(product);
        std::uint64_t hi = static_cast<std::uint64_t>(product >> 64);
        return { lo, hi };
    }
#else
    inline uint128_t mul128(std::uint64_t a, std::uint64_t b) {
        // We don't want a slow software version here, so we create a compiler error.
    #error "No 128-bit multiplication support on this platform"
    }
#endif


//
// Provide _umul128 compatibility for non-MSVC platforms, matching the Windows intrinsic from <intrin.h>.
//
#if !defined(_MSC_VER)
    inline std::uint64_t _umul128(std::uint64_t a, std::uint64_t b, std::uint64_t* hi) {
        uint128_t res = mul128(a, b);
        *hi = res.hi;
        return res.lo;
    }
#else
    // For MSVC, just use the intrinsic directly.
#endif
