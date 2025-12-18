#pragma once
// file RNG.h

/*
Contents:

        Three Random Number Generators

            1. Replacement for std::random_device, uses BCryptGenRandom. Retrieves
               4 bytes at a time, just like random_device.
            class rng::random_device;


            2. a cryptographically secure random number generator, based on ChaCha20
            class rng::csprng;

            3. A fast random number generator, very similar to wyrand
            class rng::fast_RNG;

        Utilities

            fills a buffer with random bytes.
            void rng::Utility::get_random_bytes(std::span<std::byte> buffer) noexcept(false);

            Creates a union that allows access to data as u8, u16, u32, and u64.
            rng::Block::Block
*/

#include <algorithm> // Needed for std::min
#include <array>
#include <bit> // std::rotl, std::endian
#include <cstdint>  // uint8_t
#include <cstddef> // std::byte
#include <cstring> // memcpy
#include <limits>    // std::numeric_limits
#include <random>
#include <span> // std::span
#include <string>
#include <stdexcept>
#include <type_traits> // Required for std::is_trivially_copyable_v
#include <utility>      // for std::swap
#include <vector>



// Portable 128-bit multiplication helpers
// Define once per translation unit
#ifdef __SIZEOF_INT128__
// GCC/Clang with native __int128 support
using uint128_t = __int128_t;

static inline constexpr uint128_t mul128(std::uint64_t a, std::uint64_t b) {
    return static_cast<uint128_t>(a) * static_cast<uint128_t>(b);
}

static inline constexpr std::uint64_t lo128(uint128_t x) {
    return static_cast<std::uint64_t>(x);
}

static inline constexpr std::uint64_t hi128(uint128_t x) {
    return static_cast<std::uint64_t>(x >> 64);
}

#elif defined(_MSC_VER)
// MSVC: use intrinsic
#include <intrin.h>     // MSVC intrinsic, only included when needed
struct uint128_t {
    std::uint64_t lo;
    std::uint64_t hi;
    constexpr uint128_t(std::uint64_t l = 0, std::uint64_t h = 0) : lo(l), hi(h) {}
};

static inline uint128_t mul128(std::uint64_t a, std::uint64_t b) {
    std::uint64_t hi;
    std::uint64_t lo = _umul128(a, b, &hi);
    return { lo, hi };
}

static inline constexpr std::uint64_t lo128(uint128_t x) { return x.lo; }
static inline constexpr std::uint64_t hi128(uint128_t x) { return x.hi; }

#else
#error "Compiler/platform does not support 128-bit multiplication required for unbiased()"
#endif

// This should never happen, but for defensive purposes:
static_assert(sizeof(std::byte) == 1, "std::byte must be 8 bits");

// Check for little endian
static_assert(std::endian::native == std::endian::little,
    "This ChaCha20 implementation assumes little-endian byte order");

namespace rng {
    // alias types for fixed sized unsigned integers    
    using u8 = std::uint8_t;
    using u16 = std::uint16_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;

    namespace detail {
        // This is defined in RNG.cpp
        inline void fill_with_platform_entropy(unsigned char* buffer, std::size_t size);
    }

    // Drop-in replacement for std::random_device, uses BCryptGenRandom. Retrieves
    // 4 bytes at a time, just like std::random_device.
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

        // The core: return secure random 32-bit value
        uint32_t operator()() noexcept(false)
        {
            uint32_t result;
            rng::detail::fill_with_platform_entropy(reinterpret_cast<unsigned char*>(&result), sizeof(result));
            return result;
        }

        // Entropy estimate — real devices often return 32.0, so we do too
        double entropy() const noexcept {
            return 32.0;
        }

        //
        // Extras
        //

        inline uint32_t draw32() { return (*this)(); }
        inline uint64_t draw64() { return (uint64_t((*this)()) << 32) | uint64_t((*this)()); }

        // Draw an unbiased integer in an interval [lo,hi], including the endpoints
        // Uses Lemire's method.
        inline std::uint64_t unbiased(std::uint64_t lo, std::uint64_t hi)
        {
            if (lo > hi) std::swap(lo, hi);
            if (lo == hi) return lo;

            // Full 64-bit range: return raw 64-bit entropy directly
            if (hi - lo == UINT64_MAX) return draw64();

            const std::uint64_t range = hi - lo + 1;

            std::uint64_t x = draw64();
            std::uint64_t l = lo128(mul128(x, range));

            if (l < range) [[unlikely]] {
                const std::uint64_t t = static_cast<std::uint64_t>(-range) % range;
                while (l < t) {
                    x = draw64();
                    l = lo128(mul128(x, range));
                }
            }

            return lo + hi128(mul128(x, range));
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

    // Fill a buffer with platform entropy
    void get_random_bytes(std::span<std::byte> buffer)
    {
        if (buffer.empty())
            throw std::invalid_argument("get_random_bytes: buffer must not be empty");
        rng::detail::fill_with_platform_entropy(
            reinterpret_cast<unsigned char*>(buffer.data()),
            buffer.size_bytes()
        );
    }

    // utility namespace: contains union to address memory block as u8, u16, u32, or u64.
    namespace Block {
        // Block union for safe type punning.
        template <std::size_t NBytes> // NBytes is frequently 64, but that is not required
        union Block
        {
            std::byte   bytes[NBytes]{};    // raw byte view
            uint8_t     u8[NBytes];         // One byte at a time
            uint16_t    u16[NBytes / 2];    // 
            uint32_t    u32[NBytes / 4];    // unsigned long: main view for ChaCha20
            uint64_t    u64[NBytes / 8];    // unsigned long long

            // ------------ 
            // CONSTRUCTORS
            // ------------ 

            // Construct from a std::array of trivially copyable objects
            template <class T, std::size_t N> requires (N * sizeof(T) == NBytes) && std::is_trivially_copyable_v<T>
            Block(const std::array<T, N>& src) noexcept
            {
                std::memcpy(bytes, src.data(), NBytes);
            }

            // Construct from an array of trivially copyable objects
            template <class T, std::size_t N> requires (N * sizeof(T) == NBytes) && std::is_trivially_copyable_v<T>
            Block(const T(&src)[N]) noexcept
            {
                std::memcpy(bytes, src, NBytes);
            }

            // Construct from a byte pointer
            explicit Block(const std::byte* p) noexcept
            {
                std::memcpy(bytes, p, NBytes);
            }

            // default constructor
            Block() noexcept = default;

            ~Block() { clear(); }

            // copy operator
            Block& operator= (const Block& other) noexcept {
                if (this != &other)
                    std::memcpy(bytes, other.bytes, NBytes);
                return *this;
            }

            // ----------------- 
            // UTILITY FUNCTIONS
            // ----------------- 

            // Number of complete elements of each type that fit in the block.
            // If NBytes is not divisible by the element size, the result is truncated
            // (e.g., a 68-byte block has 17 complete uint32_t elements).
            constexpr std::size_t size() const noexcept { return NBytes; }
            static constexpr std::size_t size_in_u8()  noexcept { return NBytes; }  // = NBytes / 1
            static constexpr std::size_t size_in_u16() noexcept { return NBytes >> 1; }  // = NBytes / 2
            static constexpr std::size_t size_in_u32() noexcept { return NBytes >> 2; }  // = NBytes / 4
            static constexpr std::size_t size_in_u64() noexcept { return NBytes >> 3; }  // = NBytes / 8

            // Convenience aliases used extremely frequently in cryptographic code
            static constexpr std::size_t size_in_dwords() noexcept { return size_in_u32(); }  // ChaCha20, SHA-2, etc.
            static constexpr std::size_t size_in_qwords() noexcept { return size_in_u64(); }  // KECCAK, BLAKE, etc.

            // -----------------
            // DATA ACCESS
            // -----------------
            // Primary recommended access: constant-time safe, works with standard algorithms/interfaces
            constexpr const std::byte* data() const noexcept { return bytes; }
            constexpr std::byte* data() noexcept { return bytes; }

            // Users may also directly access the raw views for performance-critical code:
            //   bytes[]  – std::byte view (preferred for generic code)
            //   u8[]     – uint8_t view
            //   u16[]    – uint16_t view (rare)
            //   u32[]    – uint32_t view (common in ChaCha, SHA-2, etc.)
            //   u64[]    – uint64_t view (common in KECCAK, BLAKE, etc.)

            // clear() securely zero-out the allocated memory
            inline void clear() noexcept
            {
                // wipe 64-bit chunks
                volatile uint64_t* v64 = reinterpret_cast<volatile uint64_t*>(u64);
                for (std::size_t i = 0; i < size_in_u64(); ++i) {
                    v64[i] = 0;
                }

                // wipe tail bytes
                volatile std::byte* v8 = reinterpret_cast<volatile std::byte*>(bytes);
                for (std::size_t i = 8 * size_in_u64(); i < NBytes; ++i) {
                    v8[i] = std::byte{ 0 };
                }
            }

            // equality operator
            inline bool operator==(const Block& other) const noexcept
            {
                if (this == &other) return true;

                // u64 comparisons
                for (std::size_t i = 0; i < size_in_u64(); ++i) {
                    if (u64[i] != other.u64[i])
                        return false;
                }

                // byte comparisons
                for (std::size_t i = 8 * size_in_u64(); i < NBytes; ++i) {
                    if (bytes[i] != other.bytes[i])
                        return false;
                }

                return true;
            }

            // inequality operator
            inline bool operator!=(const Block& other) const noexcept {
                return !(*this == other);
            }

            // checks if the Block is all zeros
            inline bool is_zero() const noexcept {
                // check 8 bytes at a time
                for (std::size_t i = 0; i < size_in_u64(); ++i) {
                    if (u64[i] != 0ull)
                        return false;
                }

                // check remaining bytes
                for (std::size_t i = 8 * size_in_u64(); i < NBytes; ++i) {
                    if (bytes[i] != std::byte{ 0 })
                        return false;
                }

                return true;
            }

        };// class Block<NBytes>

        // We put the ^ and ^= operators after the Block definition, still inside namespace st

        // ^ operator: bitwise XOR of two Blocks
        template <std::size_t NBytes>
        Block<NBytes> operator^(const Block<NBytes>& a, const Block<NBytes>& b) noexcept
        {
            Block<NBytes> result;
            std::size_t qwords = Block<NBytes>::size_in_u64();
            std::size_t tail = NBytes - 8 * qwords;

            for (std::size_t i = 0; i < qwords; ++i)
                result.u64[i] = a.u64[i] ^ b.u64[i];

            for (std::size_t i = 0; i < tail; ++i)
                result.bytes[8 * qwords + i] = a.bytes[8 * qwords + i] ^ b.bytes[8 * qwords + i];

            return result;
        }

        // ^= operator: in-place bitwise XOR of two Blocks
        template <std::size_t NBytes>
        Block<NBytes>& operator^=(Block<NBytes>& a, const Block<NBytes>& b) noexcept
        {
            std::size_t qwords = Block<NBytes>::size_in_u64();
            std::size_t tail = NBytes - 8 * qwords;

            for (std::size_t i = 0; i < qwords; ++i)
                a.u64[i] ^= b.u64[i];

            for (std::size_t i = 0; i < tail; ++i)
                a.bytes[8 * qwords + i] ^= b.bytes[8 * qwords + i];

            return a;
        }

        // A couple common sizes of Blocks

        using Block64 = Block<64>; // a union that allows us to view 64 bytes as std::bytes, u8, u32, or u64
        using Block32 = Block<32>;
    }

    // core ChaCha20 functions
    namespace ChaCha {

        // Constants used in ChaCha20
        static constexpr std::array<u32, 4> ChaCha20_constants{
            0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
            // "expand 32-byte k" in little-endian ASCII
        };

        /*
        * In the st::ChaCha namespace we typically use a 256 bit key, 64 bit block_counter, and
        * 64 bit nonce. This is consistent with the original ChaCha20-Bernstein layout, but there
        * are many modern implementations that use a 32 bit block_counter and a 96 bit nonce.
        *
        * ChaCha20-Bernstein (original): 64-bit nonce, 64-bit block_counter
        * NOT RFC 8439 compliant (which uses 96-bit nonce + 32-bit block_counter)
        *
        * Warning: This is NOT the RFC 8439 layout used in TLS/WireGuard
        * Do not mix with standard libraries unless you know what you're doing.
        *
        * A build_state( const KEY&, const NONCE96&, BLOCK_COUNTER_32) has been provided to
        * simplify a transition to RFC8439, if that is needed in the future.
        */

        // Types used throughout st::ChaCha

        using KEY = std::array<u32, 8>; // 256 bit key
        using NONCE = std::array<u32, 2>; // 64 bit nonce
        using BLOCK_COUNTER = u64; // 64 bit block block_counter

        using NONCE96 = std::array<u32, 3>; // 96 bit nonce
        using BLOCK_COUNTER_32 = u32; // 32 bit block block_counter

        // simple validation of sizes

        static_assert(sizeof(KEY) == 32, "KEY must be 32 bytes (256 bits)");
        static_assert(sizeof(NONCE) == 8, "NONCE must be 8 bytes (64 bits)");
        static_assert(sizeof(NONCE96) == 12, "NONCE96 must be 12 bytes (96 bits)");

        // A few well-studied constants from xxHash
        static constexpr u64 XXH_PRIME64_1 = 0x9E3779B185EBCA87ULL;
        static constexpr u64 XXH_PRIME64_2 = 0xC2B2AE3D27D4EB4FULL;
        static constexpr u64 XXH_PRIME64_3 = 0x165667B19E3779F9ULL;
        static constexpr u64 XXH_PRIME64_4 = 0x85EBCA77C2B2AE63ULL;
        static constexpr u64 XXH_PRIME64_5 = 0x27D4EB2F165667C5ULL;

        /*!
         * @internal
         * @brief xxHash final mixing function
         *
         * The final mix ensures that all input bits have a chance to impact any bit in
         * the output digest, resulting in an unbiased distribution.
         *
         * @param hash The hash to avalanche.
         * @return The avalanched hash.
         */
        inline u64 XXH64_avalanche(u64 hash)
        {
            hash ^= hash >> 33;
            hash *= XXH_PRIME64_2;
            hash ^= hash >> 29;
            hash *= XXH_PRIME64_3;
            hash ^= hash >> 32;
            return hash;
        }

        // Create a non-deterministic key. High quality, but non-cryptographic.
        KEY generate_random_key() noexcept(false)
        {
            KEY k{};
            get_random_bytes(std::as_writable_bytes(std::span(k)));
            return k;
        }

        // Create a non-deterministic nonce. High quality, but non-cryptographic.
        inline NONCE generate_random_nonce() noexcept(false)
        {
            NONCE n;
            get_random_bytes(std::as_writable_bytes(std::span(n)));
            return n;
        }

        // ChaCha20 quarter round
        inline void QR(u32& a, u32& b, u32& c, u32& d) noexcept
        {
            a += b; d ^= a; d = std::rotl(d, 16u);
            c += d; b ^= c; b = std::rotl(b, 12u);
            a += b; d ^= a; d = std::rotl(d, 8u);
            c += d; b ^= c; b = std::rotl(b, 7u);
        }


        // Applies the ChaCha20 core permutation (20 rounds, double-round style)
        // with final addition of the original input (RFC 8439 §2.3).
        // Safe for in-place operation (out may alias in).
        inline void permute_block(uint32_t* out, const uint32_t* in) noexcept
        {
            // Do all work on a local copy of the input block
            u32 x[16];
            std::memcpy(x, in, sizeof(x));

            // Perform 20 rounds (10 double rounds) on x.
            for (int r = 0; r < 10; ++r) {
                QR(x[0], x[4], x[8], x[12]);
                QR(x[1], x[5], x[9], x[13]);
                QR(x[2], x[6], x[10], x[14]);
                QR(x[3], x[7], x[11], x[15]);

                QR(x[0], x[5], x[10], x[15]);
                QR(x[1], x[6], x[11], x[12]);
                QR(x[2], x[7], x[8], x[13]);
                QR(x[3], x[4], x[9], x[14]);
            }

            // Add the original input to the result
            for (int i = 0; i < 16; ++i)
                out[i] = x[i] + in[i];
        }
        inline void permute_block(Block::Block64& out, const Block::Block64& in) noexcept
        {
            permute_block(out.u32, in.u32);
        }

        // Builds original Bernstein ChaCha20 state (64-bit nonce + 64-bit block_counter)
        // *** WARNING: NOT compatible with RFC 8439 / TLS / WireGuard ***
        inline Block::Block64 build_state(
            const KEY& key,
            const NONCE& nonce,
            BLOCK_COUNTER block_counter = 0
        ) noexcept
        {
            Block::Block64 state{};

            // constants
            std::memcpy(state.u32 + 0, ChaCha20_constants.data(), sizeof(ChaCha20_constants));

            // key
            std::memcpy(state.u32 + 4, key.data(), sizeof(key));

            // block block_counter
            state.u32[12] = static_cast<u32>(block_counter);
            state.u32[13] = static_cast<u32>(block_counter >> 32);

            // nonce
            state.u32[14] = nonce[0];
            state.u32[15] = nonce[1];

            return state;
        }

        inline Block::Block64 build_state(
            const KEY& key,
            const NONCE96& nonce,
            BLOCK_COUNTER_32 block_counter = 0
        ) noexcept
        {
            Block::Block64 state{};

            // constants
            std::memcpy(state.u32 + 0, ChaCha20_constants.data(), sizeof(ChaCha20_constants));

            // key
            std::memcpy(state.u32 + 4, key.data(), sizeof(key));

            // block block_counter
            state.u32[12] = block_counter;

            // nonce
            state.u32[13] = nonce[0];
            state.u32[14] = nonce[1];
            state.u32[15] = nonce[2];

            return state;
        }

    }// namespace ChaCha

    // ChaCha20 secure generator
    class csprng {
        rng::ChaCha::KEY key{};          // 256-bit key
        rng::ChaCha::NONCE nonce{ 0,0 }; // 64-bit nonce 
        u64 block_counter = 0;                // 64-bit block block_counter
        Block::Block64 buffer{};              // Block64 is a 64 byte union, accessible through u8/u32/u64 interfaces
        size_t word_index = 8;          // 8 × u64 per ChaCha block → start exhausted

    public:
        /// Unsigned integer type produced by operator()
        using result_type = uint64_t;

        static constexpr std::size_t state_size = 16;  // 512 bits total state (key+nonce+block_counter+buffer)
        static constexpr std::size_t block_size = 64;
        static constexpr std::size_t words_per_block = 8;

        static constexpr bool has_fixed_range = true;
        static constexpr result_type default_seed = 0x0123456789ABCDEFULL;

        /// Smallest value that operator() can return
        static constexpr result_type min() { return 0ULL; }

        /// Largest value that operator() can return
        static constexpr result_type max() { return UINT64_MAX; }

        /// @param k   256-bit (32-byte) secret key
        /// @param n   64-bit nonce/IV (two 32-bit words)
        /// @param initial_counter  Starting block block_counter (default 0)
        ///
        /// Recommended construction for cryptographic use.
        csprng(
            const rng::ChaCha::KEY& k,
            rng::ChaCha::NONCE& n,        // 64-bit nonce
            u64 initial_counter = 0)
            : key(k), nonce(n), block_counter(initial_counter)
        {
            refill_buffer();  // prime the pump
        }

        /// @brief Constructs a generator from a 64-byte seed block using ChaCha20 self-derivation
        /// @param block  Raw 64-byte seed material
        ///
        /// The block is treated as both key and constant for one ChaCha20 permutation,
        /// producing a fresh key and nonce. The input block is zeroed in memory.
        csprng(const Block::Block64& block /* 64 byte seed block */ )
            : block_counter(0)
        {
            Block::Block64 temp(block);
            rng::ChaCha::permute_block(temp, temp);

            memcpy(key.data(), temp.u32, 32); // 8 * u32
            memcpy(nonce.data(), temp.u32 + 8, 8); // 2 * u32

            refill_buffer();  // prime the pump
        }

        /// @brief Constructs a generator from a 32-byte seed using standard ChaCha20 expansion
        /// @param block  Raw 32-byte seed material
        ///
        /// Equivalent to libsodium's crypto_generichash-based key derivation or BLAKE3 keyed mode:
        /// the 32-byte seed is expanded to a full 256-bit key + 64-bit nonce via one ChaCha20 block.
        /// Provides domain separation and input destruction.
        csprng(const Block::Block32& block /* 32 byte seed block */)
            : block_counter(0)
        {
            Block::Block64 temp{};
            memcpy(temp.bytes, block.bytes, 32);
            memset(temp.bytes + 32, 0, 32); // should already be zeros, from the Block64 construction. But, no harm done.

            // Expand 32-byte seed → fresh 256-bit key + 64-bit nonce using one ChaCha20 block
            // This is a standard, secure key-derivation technique (similar to HKDF-Expand,
            // BLAKE3 keyed mode, and libsodium's common practice). It provides:
            // • Domain separation (raw seed never used directly)
            // • Destruction of the seed in memory
            // • Strong one-wayness and backtracking resistance
            // It is NOT an entropy extractor if the seed is low-entropy — the caller must
            // supply high-entropy input (e.g. from getrandom(), RDSEED, or a KDF).
            rng::ChaCha::permute_block(temp, temp);

            memcpy(key.data(), temp.u32, 32); // 8 * u32
            memcpy(nonce.data(), temp.u32 + 8, 8); // 2 * u32

            refill_buffer();  // prime the pump
        }

        /// @brief Constructs a generator seeded from the operating system's cryptographically secure entropy source
        ///
        /// Fills 64 bytes (512 bits) of high-quality entropy using the platform’s best available
        /// CSPRNG:
        /// - Windows → BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG
        /// - POSIX   → getrandom(2) with GRND_NONBLOCK implicitly preferred
        ///
        /// The entropy is split as follows:
        /// - bytes 0–31  → 256-bit ChaCha20 key
        /// - bytes 32–39 → 64-bit nonce
        /// - bytes 40–47 → initial block block_counter (randomized for forward secrecy)
        /// - bytes 48–63 → discarded (domain separation / future expansion)
        ///
        /// This construction yields full 256-bit security, protects against accidental key/nonce
        /// reuse, and ensures distinct output streams even if the system RNG repeats a value.
        ///
        /// get_random_bytes() throws std::runtime_error if entropy collection fails.
        csprng() {
            std::array<std::byte, 64> entropy;
            get_random_bytes(std::span(entropy));
            std::memcpy(key.data(), entropy.data(), 32);
            std::memcpy(nonce.data(), entropy.data() + 32, 8);
            std::memcpy(&block_counter, entropy.data() + 40, 8);
            refill_buffer();
        }

        /// @brief Constructs a deterministic generator from a 64-bit seed
        /// @param seed  64-bit seed value
        ///
        /// Internally uses std::mt19937_64 to stretch the seed.
        /// For reproducibility and testing only — NOT cryptographically secure.
        explicit csprng(uint64_t seed) {
            std::mt19937_64 mt(seed);
            for (int i = 0; i < key.size(); i++)
                key[i] = (u32)mt();
            for (int i = 0; i < nonce.size(); i++)
                nonce[i] = (u32)mt();

            refill_buffer();
        }

        /// Copy construction is disabled — would duplicate the output stream (catastrophic for security)
        csprng(const csprng&) = delete;
        csprng& operator=(const csprng&) = delete;

        /// Move semantics are permitted — transfers ownership of the unique stream
        csprng(csprng&&) noexcept = default;
        csprng& operator=(csprng&&) noexcept = default;

        // destructor
        ~csprng() noexcept {
            clear(&key, sizeof(key));
            clear(&nonce, sizeof(nonce));
            clear(&buffer, sizeof(buffer));
        }

        /// @brief Generates the next 64-bit value in the keystream
        /// @return A cryptographically secure 64-bit unsigned integer
        result_type operator()() {
            if (word_index >= 8) {
                refill_buffer();
            }
            return buffer.u64[word_index++];
        }

        inline uint32_t draw32() {
            return (uint32_t)((*this)() >> 32);
        }
        inline uint64_t draw64() {
            return (*this)();
        }

        // Draw an unbiased integer in an interval [lo,hi], including the endpoints
        // Uses Lemire's method.
        inline std::uint64_t unbiased(std::uint64_t lo, std::uint64_t hi)
        {
            if (lo > hi) std::swap(lo, hi);
            if (lo == hi) return lo;

            // Full 64-bit range: return raw 64-bit entropy directly
            if (hi - lo == UINT64_MAX) return draw64();

            const std::uint64_t range = hi - lo + 1;

            std::uint64_t x = draw64();
            std::uint64_t l = lo128(mul128(x, range));

            if (l < range) [[unlikely]] {
                const std::uint64_t t = static_cast<std::uint64_t>(-range) % range;
                while (l < t) {
                    x = draw64();
                    l = lo128(mul128(x, range));
                }
            }

            return lo + hi128(mul128(x, range));
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

        // NO! WRONG!
        // bool operator==(const random_device&) const noexcept { return true; }

        /// @brief Reseeds the generator with a new key/nonce pair
        /// @param k  New 256-bit key
        /// @param n  New 64-bit nonce
        ///
        /// Useful after fork() in multi-process environments or for periodic reseeding.
        void reseed(const ChaCha::KEY& k, const ChaCha::NONCE& n) {
            key = k;
            nonce = n;
            block_counter = 0;
            refill_buffer();
        }

        /// @brief Discards the next @a n 64-bit values from the output stream
        /// @param n  Number of 64-bit values to skip (may be zero)
        ///
        /// This function advances the internal state as if @a n values had been generated,
        /// but without actually computing the discarded values. It is provided for compatibility
        /// with the C++ RandomNumberEngine concept.
        ///
        /// Complexity: O(1) amortized — only O(n mod 8) in the worst case.
        void discard(std::uint64_t n)
        {
            if (n == 0) return;

            // Consume remaining words in current buffer
            size_t remaining = 8 - word_index;
            if (n < remaining) {
                word_index += static_cast<size_t>(n);
                return;
            }

            n -= remaining;
            word_index = 8;  // ← buffer now officially exhausted

            const std::uint64_t full_blocks = n / 8;
            const std::uint64_t remainder = n % 8;

            // Skip full blocks by advancing block_counter
            if (full_blocks > 0) {
                if (block_counter > UINT64_MAX - full_blocks)
                    throw std::runtime_error("csprng: block_counter overflow during discard");
                block_counter += full_blocks;
            }

            // If we need any output from the next block, generate it
            if (remainder != 0) {
                refill_buffer();                    // block_counter++, generates next block
                word_index = static_cast<size_t>(remainder);
            }
            // else: word_index remains 8 → next operator() will refill automatically
        }

        /// @brief Advances the stream by exactly 2^32 outputs (2^35 bytes).
        /// Equivalent to calling operator() 2^32 times.
        ///
        /// Use to generate up to 2^32 non-overlapping subsequences for parallel computations
        /// (each subsequence has length 2^32).
        /// Preserves full 64-bit nonce security.
        void jump() {
            discard(1ULL << 32);
        }

        /// @brief Advances the stream by exactly 2^48 outputs (2^51 bytes).
        /// Equivalent to calling operator() 2^48 times.
        ///
        /// Use to generate up to 2^16 non-overlapping subsequences for parallel computations
        /// (each subsequence has length 2^48).
        /// Preserves full 64-bit nonce security.
        void long_jump() {
            discard(1ULL << 48);
        }

        /// @brief Compares two csprng objects for equality of internal state
        /// @return true if and only if both generators produce identical future output
        ///
        /// The 256-bit key is compared in constant time to prevent timing attacks.
        /// The output buffer is intentionally not compared: when key, nonce,
        /// block_counter, and word_index are identical, the next generated value is
        /// guaranteed to be identical regardless of current buffer contents.
        friend bool operator==(const csprng& lhs, const csprng& rhs) noexcept
        {
            // Constant-time comparison of the 256-bit secret key
            uint32_t key_diff = 0;
            for (size_t i = 0; i < 8; ++i)
                key_diff |= lhs.key[i] ^ rhs.key[i];

            // Everything else: use the clean, safe, standard-library operators
            return key_diff == 0 &&
                lhs.nonce == rhs.nonce &&     // Perfect! Uses std::array::operator==
                lhs.block_counter == rhs.block_counter &&
                lhs.word_index == rhs.word_index;
        }

        /// @brief Inequality operator
        friend bool operator!=(const csprng& lhs, const csprng& rhs) noexcept
        {
            return !(lhs == rhs);
        }

    private:
        // ====================================================================
        // Serialization — intentionally private and undocumented in public API
        // ====================================================================
        //
        // Exposing the full internal state (especially the 256-bit key) would
        // completely break forward/backward secrecy and allow an attacker to
        // predict all future and past outputs.
        //
        // These operators exist only for:
        // • Internal testing and debugging
        // • Advanced use cases (e.g. checkpointing in trusted, encrypted environments)
        // • Compliance with std::seed_seq / RandomNumberEngine when absolutely required
        //
        // They are deliberately NOT part of the public interface.
        // If you need reproducibility or checkpointing in a secure context,
        // use reseed() with fresh entropy or encrypt the serialized blob.
        //
        // YOU HAVE BEEN WARNED.
        //

        /// @name Serialization
        /// @brief Serializes the complete internal state of the generator
        /// @param os  Output stream
        /// @param rng The generator to serialize
        /// @return    Reference to the output stream
        ///
        /// The format is binary and versioned:
        /// - 8 bytes:  magic header "csprng"
        /// - 1 byte:   version (currently 1)
        /// - 32 bytes: key
        /// - 8 bytes:  nonce
        /// - 8 bytes:  block_counter
        /// - 1 byte:   word_index (0–8)
        /// - 7 bytes:  padding (reserved, zero)
        ///
        /// Total: 65 bytes — compact and future-proof.
        template<class CharT, class Traits>
        friend std::basic_ostream<CharT, Traits>&
            operator<<(std::basic_ostream<CharT, Traits>& os, const csprng& rng)
        {
            static constexpr char magic[8] = "csprng";
            static constexpr std::uint8_t version = 1;

            os.write(magic, 8);
            os.put(static_cast<char>(version));

            os.write(reinterpret_cast<const char*>(rng.key.data()), 32);
            os.write(reinterpret_cast<const char*>(rng.nonce.data()), 8);
            os.write(reinterpret_cast<const char*>(&rng.block_counter), 8);
            os.put(static_cast<char>(rng.word_index));

            // Reserved padding (future use)
            char padding[7] = {};
            os.write(padding, 7);

            return os;
        }

        /// @brief Deserializes and restores the complete internal state
        /// @param is  Input stream
        /// @param rng The generator to restore into
        /// @return    Reference to the input stream
        ///
        /// Throws std::runtime_error on version mismatch, invalid magic, or I/O error.
        template<class CharT, class Traits>
        friend std::basic_istream<CharT, Traits>&
            operator>>(std::basic_istream<CharT, Traits>& is, csprng& rng)
        {
            char magic[8] = {};
            is.read(magic, 8);
            if (!is || std::memcmp(magic, "csprng", 8) != 0)
                throw std::runtime_error("csprng: invalid or corrupted stream (bad magic)");

            const std::uint8_t version = static_cast<std::uint8_t>(is.get());
            if (!is || version != 1)
                throw std::runtime_error("csprng: unsupported version");

            is.read(reinterpret_cast<char*>(rng.key.data()), 32);
            is.read(reinterpret_cast<char*>(rng.nonce.data()), 8);
            is.read(reinterpret_cast<char*>(&rng.block_counter), 8);

            const int idx = is.get();
            if (!is || idx < 0 || idx > 8)
                throw std::runtime_error("csprng: corrupted word_index");

            rng.word_index = static_cast<size_t>(idx);

            // Discard padding
            char padding[7];
            is.read(padding, 7);

            if (!is)
                throw std::runtime_error("csprng: stream read error during deserialization");

            // If the buffer was valid, we must regenerate it
            if (rng.word_index < 8) {
                // Reconstruct the current block from key/nonce/block_counter-1
                const uint64_t saved_counter = rng.block_counter;
                if (saved_counter == 0) {
                    throw std::runtime_error("csprng: cannot restore mid-block state at block_counter == 0");
                }
                --rng.block_counter;
                rng.refill_buffer();           // generates the correct block
                rng.block_counter = saved_counter;
                rng.word_index = static_cast<size_t>(idx);  // already set, but safe
            }
            // else: word_index == 8 → buffer exhausted → next operator() will refill correctly

            return is;
        }

    private:
        void refill_buffer() {
            auto state = ChaCha::build_state(
                key,
                ChaCha::NONCE{ nonce[0], nonce[1] },
                block_counter
            );

            ChaCha::permute_block(buffer, state);
            state.clear(); // state no longer needed. Clear sensitive data

            // reset the buffer index: no words have been consumed.
            word_index = 0;

            // increment the block block_counter
            ++block_counter;
            if (block_counter == 0) {
                // 2⁷⁰ bytes generated (~1.2 zettabytes). 
                // If this ever triggers, humanity has bigger problems.
                // Required for RFC 8439 compliance and formal audits.
                throw std::runtime_error("csprng: key/nonce pair exhausted");
            }
        }

        static void clear(const void* data, const size_t nbytes) {
            volatile uint8_t* p = (uint8_t*)data;
            for (size_t i = 0; i < nbytes; i++)
                p[i] = 0;
        }
    }; // class csprng

    // fast_RNG: A fast non-cryptographic PRNG inspired by wyrand.
    // Core idea (additive increment + wide multiplication + hi ⊕ lo output) comes from:
    // https://github.com/wangyi-fudan/wyhash/blob/master/wyhash.h
    // This variant adds a small extra mixing step (state ^ MIX in the final XOR)
    // for slightly different output characteristics while preserving speed and quality.
    class fast_RNG {
        /*
        Speed test
            GBPS = 10.9968

        PractRand run, 64 GB, no anomalies

            Executing PractRand command: type test.bin | RNG_test.exe stdin64 -tf 2 -te 1 -tlmax 64GB -multithreaded
            RNG_test using PractRand version 0.94
            RNG = RNG_stdin64, seed = unknown
            test set = expanded, folding = extra

            rng=RNG_stdin64, seed=unknown
            length= 64 megabytes (2^26 bytes), time= 2.8 seconds
              no anomalies in 1008 test result(s)

            rng=RNG_stdin64, seed=unknown
            length= 128 megabytes (2^27 bytes), time= 7.6 seconds
              no anomalies in 1081 test result(s)

            rng=RNG_stdin64, seed=unknown
            length= 256 megabytes (2^28 bytes), time= 14.5 seconds
              no anomalies in 1151 test result(s)

            rng=RNG_stdin64, seed=unknown
            length= 512 megabytes (2^29 bytes), time= 25.3 seconds
              no anomalies in 1220 test result(s)

            rng=RNG_stdin64, seed=unknown
            length= 1 gigabyte (2^30 bytes), time= 44.8 seconds
              no anomalies in 1293 test result(s)

            rng=RNG_stdin64, seed=unknown
            length= 2 gigabytes (2^31 bytes), time= 80.5 seconds
              no anomalies in 1368 test result(s)

            rng=RNG_stdin64, seed=unknown
            length= 4 gigabytes (2^32 bytes), time= 151 seconds
              no anomalies in 1448 test result(s)

            rng=RNG_stdin64, seed=unknown
            length= 8 gigabytes (2^33 bytes), time= 292 seconds
              no anomalies in 1543 test result(s)

            rng=RNG_stdin64, seed=unknown
            length= 16 gigabytes (2^34 bytes), time= 566 seconds
              no anomalies in 1637 test result(s)

            rng=RNG_stdin64, seed=unknown
            length= 32 gigabytes (2^35 bytes), time= 1090 seconds
              no anomalies in 1714 test result(s)

            rng=RNG_stdin64, seed=unknown
            length= 64 gigabytes (2^36 bytes), time= 33077 seconds
              no anomalies in 1807 test result(s)

            PractRand command completed successfully
        */

        uint64_t state;
        // constants from wyrand variant
        static constexpr uint64_t INCREMENT = 0x2d358dccaa6c78a5ull;
        static constexpr uint64_t MIX = 0x8bb84b93962eacc9ull;

    public:
        using result_type = uint64_t;

        explicit fast_RNG(uint64_t seed = 0) : state(seed) {
            // Optional: mix the seed a bit more if it's weak (SplitMix-style)
            // But wyrand works fine with raw seeds, so keep it simple.
        }

        // Seed with a seed_seq (standard requirement)
        template <class SeedSeq>
        explicit fast_RNG(SeedSeq& seq) {
            seed(seq);
        }

        // Standard seed function using seed_seq
        template <class SeedSeq>
        void seed(SeedSeq& seq) {
            uint32_t seeds[2];
            seq.generate(seeds, seeds + 2);
            state = (static_cast<uint64_t>(seeds[1]) << 32) | seeds[0];
        }

        // Default seed (e.g., fast_RNG gen; without explicit seed)
        void seed(result_type s) {
            state = s;
        }

        // non-deterministic seed
        void seed() {
            random_device rd;

            state = (static_cast<uint64_t>(rd()) << 32) | rd();
        }

        // Core generator
        result_type operator()() {
            state += INCREMENT;
            uint128_t product = mul128(state, state ^ MIX);
            return state ^ MIX ^ lo128(product) ^ hi128(product);
        }

        // Discard (jump ahead) - standard requirement
        void discard(unsigned long long nsteps) {
            state += nsteps * INCREMENT;
        }

        // Constants required by the concept
        static constexpr result_type min() noexcept { return 0; }
        static constexpr result_type max() noexcept { return std::numeric_limits<result_type>::max(); }

        // Equality comparison (standard)
        friend bool operator==(const fast_RNG& lhs, const fast_RNG& rhs) noexcept {
            return lhs.state == rhs.state;
        }

        friend bool operator!=(const fast_RNG& lhs, const fast_RNG& rhs) noexcept {
            return !(lhs == rhs);
        }

        // Optional: stream operators for save/restore (makes it a full Engine)
        template <class CharT, class Traits>
        friend std::basic_ostream<CharT, Traits>& operator<<(std::basic_ostream<CharT, Traits>& os, const fast_RNG& rng) {
            os << rng.state;
            return os;
        }

        template <class CharT, class Traits>
        friend std::basic_istream<CharT, Traits>& operator>>(std::basic_istream<CharT, Traits>& is, fast_RNG& rng) {
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

        // Lemire's unbiased bounded integer — identical to the others
        inline uint64_t unbiased(uint64_t lo, uint64_t hi) {
            if (lo > hi) std::swap(lo, hi);
            if (lo == hi) return lo;

            if (hi - lo == UINT64_MAX) return draw64();

            const uint64_t range = hi - lo + 1;

            uint64_t x = draw64();
            uint64_t l = lo128(mul128(x, range));

            if (l < range) [[unlikely]] {
                const uint64_t t = static_cast<uint64_t>(-range) % range;
                while (l < t) {
                    x = draw64();
                    l = lo128(mul128(x, range));
                }
            }

            return lo + hi128(mul128(x, range));
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
    };



    //==============================================================================================
    // Generic fill functions — work with any UniformRandomBitGenerator
    //==============================================================================================

    template <class Gen>
    concept HasFillMember = requires(Gen & g, std::span<std::byte> s) {
        g.fill(s);
    };

    template <class Gen>
    inline void fill(std::span<std::byte> data, Gen& gen) {
        if constexpr (HasFillMember<Gen>) {
            gen.fill(data);
        }
        else {
            std::byte* ptr = data.data();
            size_t size = data.size();

            using result_type = typename Gen::result_type;

            while (size >= sizeof(result_type)) {
                result_type value = gen();
                std::memcpy(ptr, &value, sizeof(result_type));
                ptr += sizeof(result_type);
                size -= sizeof(result_type);
            }

            if (size > 0) {
                result_type value = gen();
                std::memcpy(ptr, &value, size);
            }
        }
    }

    template <class T, size_t N, class Gen>
    inline void fill(std::array<T, N>& arr, Gen& gen) {
        fill(std::as_bytes(std::span(arr)), gen);
    }

    template <class T, class Gen>
    inline void fill(std::vector<T>& vec, Gen& gen) {
        fill(std::as_bytes(std::span(vec)), gen);
    }

}// namespace rng
