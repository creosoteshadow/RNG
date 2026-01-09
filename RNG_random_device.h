#pragma once
#define NOMINMAX

#include "common.h"

//==============================================================================================
// RNG::random_device -- alternative to std::random_device. Uses OS entropy sources when available,
// refuses to compile on platforms without secure entropy sources.
//==============================================================================================
namespace RNG {

    /*
        RNG::random_device

        A non-deterministic random number generator that produces uniformly distributed
        unsigned integers using cryptographically secure entropy from the operating system.

        This class is designed as a drop-in replacement for std::random_device.
        On Windows it uses BCryptGenRandom; on Unix-like systems it prefers getrandom()
        with fallback to /dev/urandom.

        It provides true randomness suitable for cryptographic purposes or seeding
        pseudo-random engines, but repeated calls may block or degrade in performance
        if system entropy is temporarily exhausted.

        Defined in header "RNG.h"
            namespace RNG {
                class random_device;
            }

        Member types
            result_type	uint32_t

        Member functions
            Constructors
                (1) random_device() noexcept
                    Default constructor. Initializes the generator using the platform's
                    default entropy source.

                (2) explicit random_device(const std::string& token)
                    Constructs the generator, ignoring the token parameter.
                    Provided for compatibility with std::random_device, which accepts
                    a token to select a specific entropy source on some implementations.
                    Here the token is ignored; all instances use the same system source.

                Note: Copy construction and copy assignment are deleted (non-copyable).

            Member functions
                operator=
                    DELETED. Copying not allowed.

                bool operator==(const random_device&) const noexcept;
                    Always returns true: all same source

            Generation
                result_type operator()()
                    Returns a uniformly distributed random 32-bit_count value.
                    May throw if entropy collection fails.

                uint32_t draw32()
                    Equivalent to operator(). Provided for clarity.

                uint64_t draw64()
                    Returns a uniformly distributed random 64-bit_count value by combining
                    two independent 32-bit_count draws.

                 uint64_t unbiased(uint64_t lo, uint64_t hi)
                    Returns a uniformly distributed integer in the closed interval [lo, hi]
                    with no modulo bias, using Lemire's method.
                    The endpoints are inclusive. If lo > hi, the arguments are swapped.

                 void fill(std::span<std::byte> data)
                    Fills the specified byte span with cryptographically secure random bytes.
                    Optimized for large buffers by requesting 64-bit_count chunks when possible.

                 template<class T, size_t N>
                 void fill(std::array<T, N>& arr)
                    Fills the array with random values by treating it as a byte span.

                 template<class T>
                 void fill(std::vector<T>& vec)
                    Fills the vector with random values by treating its data as a byte span.

            Observers
                double entropy() const noexcept
                    Returns the estimated entropy per generated value in bits.
                    Always returns 32.0, consistent with many real std::random_device implementations.

                static constexpr result_type min() noexcept
                static constexpr result_type max() noexcept
                    Returns the inclusive lower and upper bounds of values returned by operator().

            Comparison
                bool operator==(const random_device&) const noexcept;
                    Always returns true, because all instances draw from the same
                    underlying system entropy source.

        Example
            #include <iostream>
            #include <map>
            #include <random>
            #include <string>

            int main()
            {
                RNG::random_device rd; // not std::
                std::map<int, int> hist;
                std::uniform_int_distribution<int> dist(0, 9);

                for (int n = 0; n != 20000; ++n)
                    ++hist[dist(rd)]; // Note: On some platforms (e.g., certain Linux configurations
                                      // using /dev/random), frequent calls to system entropy sources
                                      // may block if entropy is temporarily low. On Windows (using
                                      // BCryptGenRandom) and modern Unix-like systems (using getrandom()
                                      // or /dev/urandom), this is not an issue—output remains fast and
                                      // cryptographically secure.

                for (auto [x, y] : hist)
                    std::cout << x << " : " << std::string(y / 100, '*') << '\n';
            }
    */
    class random_device {
    public:
        using result_type = uint32_t;  // std::random_device uses uint32_t

        static constexpr result_type min() noexcept { return std::numeric_limits<result_type>::min(); }
        static constexpr result_type max() noexcept { return std::numeric_limits<result_type>::max(); }

        // Default constructor
        random_device() = default;

        // Disable copy (like real random_device)
        random_device(const random_device&) = delete;
        random_device& operator=(const random_device&) = delete;

        // Explicitly allow construction with a "token" string (ignored, for compatibility)
        explicit random_device(const std::string&) {}

        // The core: return secure random 32-bit_count value
        uint32_t operator()() noexcept(false)
        {
            uint32_t result;
            RNG_platform::get_entropy(reinterpret_cast<unsigned char*>(&result), sizeof(result));
            return result;
        }

        // Entropy estimate — real devices often return 32.0, so we do too
        double entropy() const noexcept {
            return 32.0;
        }

        //
        // Extras
        //

        inline uint32_t draw32() {
            uint32_t result;
            RNG_platform::get_entropy(reinterpret_cast<unsigned char*>(&result), sizeof(result));
            return result;
        }
        inline uint64_t draw64() {
            uint64_t result;
            RNG_platform::get_entropy(reinterpret_cast<unsigned char*>(&result), sizeof(result));
            return result;
        }

        // Returns a uniformly distributed integer in [lo, hi] using Lemire's unbiased method.
        // Handles all edge cases (including full 64-bit_count range) without statistical bias.
        inline std::uint64_t unbiased(std::uint64_t lower_bound, std::uint64_t upper_bound)
        {
            if (lower_bound > upper_bound) std::swap(lower_bound, upper_bound);
            if (lower_bound == upper_bound) return lower_bound;

            const std::uint64_t range = upper_bound - lower_bound + 1;
            if (range == 0) return draw64();  // overflow occured: therefore, full 64-bit_count range

            std::uint64_t x = draw64();
            std::uint64_t l, h;
            l = RNG::umul128(x, range, &h);

            if (l < range) [[unlikely]] {
                const std::uint64_t t = (std::numeric_limits<std::uint64_t>::max() - range + 1) % range;
                while (l < t) {
                    x = draw64();
                    l = RNG::umul128(x, range, &h);
                }
            }

            return lower_bound + h;
        }

        inline void fill(std::span<std::byte>data) {
            std::byte* ptr = data.data();
            size_t size = data.size();
            while (size >= 8) {
                uint64_t z = draw64();
                memcpy(ptr, &z, 8);
                ptr += 8;
                size -= 8;
            }
            if (size > 0) {
                uint64_t z = draw64();
                memcpy(ptr, &z, size);
            }
        }
        template <class T, size_t N> inline void fill(std::array<T, N>& arr)
        {
            fill(std::as_bytes(std::span(arr)));
        }
        template <class T> inline void fill(std::vector<T>& arr)
        {
            fill(std::as_bytes(std::span(arr)));
        }
        bool operator==(const random_device&) const noexcept { return true; } // all same source
    };
}
