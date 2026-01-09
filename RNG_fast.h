#pragma once

#define NOMINMAX
#include "common.h"
#include "RNG_random_device.h" // for seeding

//==============================================================================================
// RNG::fast, Fast non-cryptographic generator
//==============================================================================================
namespace RNG {

    struct xxxxxfast {
        static constexpr size_t BUFFER_SIZE = 8;

        std::uint64_t state;
        std::array<std::uint64_t, BUFFER_SIZE> buffer;
        size_t index = BUFFER_SIZE;  // start empty to force initial fill


    };
    class fast {
        /*
        fast: A fast non-cryptographic PRNG inspired by wyrand.
        Core idea (additive increment + wide multiplication + hi ⊕ lo output) comes from:
        https://github.com/wangyi-fudan/wyhash/blob/master/wyhash.h
        This variant adds a small extra mixing step (state ^ MIX in the final XOR)
        for slightly different output characteristics while preserving speed and quality.

        Speed test
            GBPS = 10.9968

        PractRand run, 64 GB, no anomalies

            Executing PractRand command: type test.bin | RNG_test.exe stdin64 -tf 2 -te 1 -tlmax 64GB -multithreaded
            RNG_test using PractRand version 0.94
            RNG = RNG_stdin64, seed = unknown
            test set = expanded, folding = extra

            RNG=RNG_stdin64, seed=unknown
            length= 64 megabytes (2^26 bytes), time= 2.8 seconds
              no anomalies in 1008 test result(s)

            RNG=RNG_stdin64, seed=unknown
            length= 128 megabytes (2^27 bytes), time= 7.6 seconds
              no anomalies in 1081 test result(s)

            RNG=RNG_stdin64, seed=unknown
            length= 256 megabytes (2^28 bytes), time= 14.5 seconds
              no anomalies in 1151 test result(s)

            RNG=RNG_stdin64, seed=unknown
            length= 512 megabytes (2^29 bytes), time= 25.3 seconds
              no anomalies in 1220 test result(s)

            RNG=RNG_stdin64, seed=unknown
            length= 1 gigabyte (2^30 bytes), time= 44.8 seconds
              no anomalies in 1293 test result(s)

            RNG=RNG_stdin64, seed=unknown
            length= 2 gigabytes (2^31 bytes), time= 80.5 seconds
              no anomalies in 1368 test result(s)

            RNG=RNG_stdin64, seed=unknown
            length= 4 gigabytes (2^32 bytes), time= 151 seconds
              no anomalies in 1448 test result(s)

            RNG=RNG_stdin64, seed=unknown
            length= 8 gigabytes (2^33 bytes), time= 292 seconds
              no anomalies in 1543 test result(s)

            RNG=RNG_stdin64, seed=unknown
            length= 16 gigabytes (2^34 bytes), time= 566 seconds
              no anomalies in 1637 test result(s)

            RNG=RNG_stdin64, seed=unknown
            length= 32 gigabytes (2^35 bytes), time= 1090 seconds
              no anomalies in 1714 test result(s)

            RNG=RNG_stdin64, seed=unknown
            length= 64 gigabytes (2^36 bytes), time= 33077 seconds
              no anomalies in 1807 test result(s)

            PractRand command completed successfully
        */

        std::uint64_t state;

        static constexpr size_t BUFFER_SIZE = 8;
        std::array<std::uint64_t, BUFFER_SIZE> buffer;
        size_t index = BUFFER_SIZE;  // start empty to force initial fill

        // constants from wyrand variant
        static constexpr uint64_t INCREMENT = 0x2d358dccaa6c78a5ull;
        static constexpr uint64_t MIX = 0x8bb84b93962eacc9ull;

    public:
        using result_type = uint64_t;

        // Default - seed from system entropy
        fast() {
            RNG::random_device rd;
            state = rd.draw64();
        }

        // seed from an integer
        fast(std::uint64_t seed = 0x2d358dccaa6c78a5ull) noexcept
            : state(seed ^ 0x9e3779b97f4a7c15ull)  // optional: better seed mixing
        {
            refill();
        }

        // Seed with a seed_seq (standard requirement)
        template <class SeedSeq>
        explicit fast(SeedSeq& seq) {
            seed(seq);
        }

        // Standard seed function using seed_seq
        template <class SeedSeq>
        void seed(SeedSeq& seq) {
            uint32_t seeds[2];
            seq.generate(seeds, seeds + 2);
            state = (static_cast<uint64_t>(seeds[1]) << 32) | seeds[0];
        }

        // Default seed (e.g., fast gen; without explicit seed)
        void seed(result_type s) {
            state = s;
        }

        // non-deterministic seed
        void seed() {
            random_device rd;

            state = (static_cast<uint64_t>(rd()) << 32) | rd();
        }

        // Core generator
        // 5.376 GB/s
        inline std::uint64_t operator()() noexcept
        {
            if (index == BUFFER_SIZE)
                refill();

            return buffer[index++];
        }

        // fill a byte buffer with n bytes of random data
        inline void bulk(uint8_t *x, size_t n) noexcept
        {
            uint8_t* p = x;
            // fill full buffer-sized chunks. Assume we need a new buffer when we start.
            while (n >= 64) {
                refill();
                memcpy(p, buffer.data(), 64);
                n -= 64;
                p += 64;
            }
            // fill any remaining bytes
            if (n > 0) {
                refill();
                memcpy(p, buffer.data(), n);
            }
            // invalidate the buffer
            index = BUFFER_SIZE;
        }

        // Discard (jump ahead) - standard requirement
        void discard(unsigned long long nsteps) {
            state += nsteps * INCREMENT;
        }

        // Constants required by the concept
        static constexpr result_type min() noexcept { return 0; }
        static constexpr result_type max() noexcept { return std::numeric_limits<result_type>::max(); }

        // Equality comparison (standard)
        friend bool operator==(const fast& lhs, const fast& rhs) noexcept {
            return lhs.state == rhs.state;
        }

        friend bool operator!=(const fast& lhs, const fast& rhs) noexcept {
            return !(lhs == rhs);
        }

        // Optional: stream operators for save/restore (makes it a full Engine)
        template <class CharT, class Traits>
        friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os, const fast& rng) {
            os << rng.state;
            return os;
        }

        template <class CharT, class Traits>
        friend std::basic_istream<CharT, Traits>& operator>>(std::basic_istream<CharT, Traits>& is, fast& rng) {
            is >> rng.state;
            return is;
        }

        // extras

        inline uint32_t draw32() {
            return static_cast<uint32_t>((*this)() >> 32);
        }

        inline uint64_t draw64() {
            return (*this)();
        }

        // Returns a uniformly distributed integer in [lo, hi] using Lemire's unbiased method.
        // Handles all edge cases (including full 64-bit_count range) without statistical bias.
        inline std::uint64_t unbiased(std::uint64_t lo, std::uint64_t hi)
        {
            if (lo > hi) std::swap(lo, hi);
            if (lo == hi) return lo;

            const std::uint64_t range = hi - lo + 1;
            if (range == 0) return draw64();  // full 64-bit_count range

            uint64_t x = draw64();
            uint64_t p_lo, p_hi; // lower and upper parts of the product
            p_lo = _umul128(x, range, &p_hi);

            if (p_lo < range) [[unlikely]] {
                const std::uint64_t t = (std::numeric_limits<std::uint64_t>::max() - range + p_lo) % range;
                while (p_lo < t) {
                    x = draw64();
                    p_lo = _umul128(x, range, &p_hi);
                }
            }

            return p_lo + p_hi;
        }

        // fill() overloads — identical to the others
        inline void fill(std::span<std::byte> data) {
            std::byte* ptr = data.data();
            size_t size = data.size();

            while (size >= 8) {
                uint64_t z = draw64();
                std::memcpy(ptr, &z, 8);
                ptr += 8;
                size -= 8;
            }

            if (size > 0) {
                uint64_t z = draw64();
                std::memcpy(ptr, &z, size);
            }
        }

        template <class T, size_t N>
        inline void fill(std::array<T, N>& arr) {
            fill(std::as_bytes(std::span(arr)));
        }

        template <class T>
        inline void fill(std::vector<T>& arr) {
            fill(std::as_bytes(std::span(arr)));
        }

        // jump() and long_jump() — consistent with csprng
        void jump() {
            discard(1ULL << 32);
        }

        void long_jump() {
            discard(1ULL << 48);
        }

    private:
        inline void refill() noexcept
        {
            for (size_t i = 0; i < BUFFER_SIZE; ++i)
            {
                uint64_t S, lo, hi;
                S = state + (i + 1) * INCREMENT;
                lo = _umul128(S, S ^ MIX, &hi);
                buffer[i] = lo ^ hi ^ S;
            }
            state += 8*INCREMENT;
            index = 0;
        }
    };

}// namespace RNG

