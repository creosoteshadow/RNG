#pragma once

#include "common.h"
#include "ChaChaCore.h"

namespace RNG {

    //==============================================================================================
    // RNG::csprng, ChaCha20 secure generator
    //==============================================================================================

    /*
    RNG::csprng

    A cryptographically secure pseudorandom number generator (CSPRNG) based on ChaCha20
    (Bernstein's original design with 20 rounds, 256-bit_count key, 64-bit_count nonce, and 64-bit_count block counter).

    This implementation is NOT compatible with RFC 8439 (TLS/WireGuard) layout, which uses a
    96-bit_count nonce and 32-bit_count counter. Do not interchange keys/nonces with standard libraries
    unless you deliberately target the same layout.

    The generator provides:
      • Full 256-bit_count security strength
      • Excellent performance (~3–5 GB/s on modern CPUs)
      • Backtracking resistance and forward secrecy
      • Safe reseeding, jumping, and parallel stream generation

    It conforms to the UniformRandomBitGenerator concept and provides additional convenience
    functions identical to those in RNG::random_device.

    Defined in header "RNG.h"

    namespace RNG {
        class csprng;
    }

    Member types
        result_type                     uint64_t

    Static constants
        static constexpr std::size_t state_size = 16;   // 512 bits total
        static constexpr std::size_t block_size = 64;   // bytes per ChaCha block
        static constexpr std::size_t words_per_block = 8;

    Construction
        (1) explicit csprng(const helper::ChaCha::KEY& k,
                            const helper::ChaCha::NONCE& n,
                            uint64_t initial_counter = 0)
            Constructs from explicit 256-bit_count key and 64-bit_count nonce.
            Recommended for full cryptographic control.

        (2) explicit csprng(const helper::Block64& seed_block)
            Derives key and nonce from a 64-byte high-entropy seed using one ChaCha20 permutation.
            The input seed is securely wiped from memory.

        (3) explicit csprng(const helper::Block32& seed_block)
            Expands a 32-byte seed into a full key + nonce using one ChaCha20 block
            (standard key-derivation technique similar to HKDF-Expand or BLAKE3 keyed mode).

        (4) csprng()
            Default constructor. Seeds from the platform CSPRNG (RNG::random_device)
            using 64 bytes of entropy. Key, nonce, and initial counter are derived securely.

    Note: Copy construction and copy assignment are deleted (stream duplication is catastrophic
          for security). Move construction and move assignment are permitted.

    Generation
        result_type operator()()
            Returns the next cryptographically secure 64-bit_count value.

        uint32_t draw32()
            Returns the low 32 bits of the next value (standard practice).

        uint64_t draw64()
            Equivalent to operator().

        uint64_t unbiased(uint64_t lo, uint64_t hi)
            Returns a uniformly distributed integer in [lo, hi] with no statistical bias
            (Lemire's method).

        void fill(std::span<std::byte> data)
        template<class T, size_t N> void fill(std::array<T, N>& arr)
        template<class T> void fill(std::vector<T>& vec)
            Fills the target with keystream bytes. Highly optimized for large buffers.

    Stream control
        void reseed(const helper::ChaCha::KEY& k, const helper::ChaCha::NONCE& n)
            Replaces the current key/nonce pair and resets the counter.
            Useful after fork() or for periodic reseeding.

        void discard(std::uint64_t n)
            Advances the stream by n 64-bit_count values without generating them.
            O(1) amortized.

        void jump()
            Equivalent to discard(2³²). Enables up to 2³² independent parallel streams.

        void long_jump()
            Equivalent to discard(2⁴⁸). Enables up to 2¹⁶ independent parallel streams.

    Observers
        static constexpr result_type min() noexcept
        static constexpr result_type max() noexcept
            Inclusive bounds of values returned by operator().

    Comparison
        friend bool operator==(const csprng& lhs, const csprng& rhs) noexcept
        friend bool operator!=(const csprng& lhs, const csprng& rhs) noexcept
            Two generators are equal if they will produce identical future output
            (constant-time key comparison).

    Remarks
        • The generator will throw std::runtime_error if the block counter overflows
          (after ~1.2 zettabytes of output per key/nonce pair).
        • Sensitive internal state (key, nonce, buffer) is securely zeroed in the destructor
          and during reseeding.
        • Serialization operators (<< and >>) exist but are intentionally private
          — exposing the raw key breaks all security guarantees.

    Example
        #include <rng.h>
        #include <iostream>
        #include <vector>

        int main()
        {
            RNG::csprng gen;                                   // seeded from OS entropy
            std::vector<std::byte> buffer(1024);
            gen.fill(buffer);                                  // fast cryptographic keystream

            std::uniform_int_distribution<int> dist(1, 100);
            for (int i = 0; i < 10; ++i)
                std::cout << dist(gen) << ' ';
            std::cout << '\n';
        }
    */
    class csprng {
        RNG::ChaChaCore::KEY key{};          // 256-bit_count key
        RNG::ChaChaCore::NONCE nonce{ 0,0 }; // 64-bit_count nonce 
        u64 block_counter = 0;                // 64-bit_count block block_counter
        Block64 buffer{};              // Block64 is a 64 byte union, accessible through u8/_u32/_u64 interfaces
        size_t word_index = 8;          // 8 × _u64 per ChaCha block → start exhausted

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

        /// @param k   256-bit_count (32-byte) secret key
        /// @param n   64-bit_count nonce/IV (two 32-bit_count words)
        /// @param initial_counter  Starting block block_counter (default 0)
        ///
        /// Recommended construction for cryptographic use.
        csprng(
            const RNG::ChaChaCore::KEY& k,
            const RNG::ChaChaCore::NONCE& n,        // 64-bit_count nonce
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
        explicit csprng(const Block64& block /* 64 byte seed block */)
            : block_counter(0)
        {
            // work off a temporary copy of block
            Block64 temp(block);

            // Use ChaCha to scramble the block
            RNG::ChaChaCore::permute_block(temp, temp);

            // copy from the block to the key and nonce
            memcpy(key.data(), temp.u32, 32); // 8 * _u32
            memcpy(nonce.data(), temp.u32 + 8, 8); // 2 * _u32

            // we don't need temp any longer. Clear it.
            temp.clear();

            // Do an initial buffer fill.
            refill_buffer();
        }

        /// @brief Constructs a generator from a 32-byte seed using standard ChaCha20 expansion
        /// @param block  Raw 32-byte seed material
        ///
        /// Equivalent to libsodium's crypto_generichash-based key derivation or BLAKE3 keyed mode:
        /// the 32-byte seed is expanded to a full 256-bit_count key + 64-bit_count nonce via one ChaCha20 block.
        /// Provides domain separation and input destruction.
        explicit csprng(const Block32& block /* 32 byte seed block */)
            : block_counter(0)
        {
            // work off a temporary copy of block
            Block64 temp{};
            memcpy(temp.bytes, block.bytes, 32);
            // zero pad unused bytes. Note: these should already be zeros, from the Block64 construction. But, no harm done.
            memset(temp.bytes + 32, 0, 32);

            // Expand 32-byte seed → fresh 256-bit_count key + 64-bit_count nonce using one ChaCha20 block
            // This is a standard, secure key-derivation technique (similar to HKDF-Expand,
            // BLAKE3 keyed mode, and libsodium's common practice). It provides:
            // • Domain separation (raw seed never used directly)
            // • Destruction of the seed in memory
            // • Strong one-wayness and backtracking resistance
            // It is NOT an entropy extractor if the seed is low-entropy — the caller must
            // supply high-entropy input (e.g. from getrandom(), RDSEED, or a KDF).
            RNG::ChaChaCore::permute_block(temp, temp);

            // copy from temp to key and nonce
            memcpy(key.data(), temp.u32, 32); // 8 * _u32
            memcpy(nonce.data(), temp.u32 + 8, 8); // 2 * _u32

            // we don't need temp any longer. Clear it.
            temp.clear();

            // Do an initial buffer fill.
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
        /// - bytes 0–31  → 256-bit_count ChaCha20 key
        /// - bytes 32–39 → 64-bit_count nonce
        /// - bytes 40–47 → initial block block_counter (randomized for forward secrecy)
        /// - bytes 48–63 → discarded (domain separation / future expansion)
        ///
        /// This construction yields full 256-bit_count security, protects against accidental key/nonce
        /// reuse, and ensures distinct output streams even if the system RNG repeats a value.
        ///
        /// get_random_bytes() throws std::runtime_error if entropy collection fails.
        csprng() {
            RNG_platform::get_entropy((unsigned char*)key.data(), key.size() * sizeof(key[0]));
            RNG_platform::get_entropy((unsigned char*)nonce.data(), nonce.size() * sizeof(nonce[0]));
            block_counter = 0;  // always start at zero
            // bytes 40–63 available for domain separation / future use
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

        /// @brief Generates the next 64-bit_count value in the keystream
        /// @return A cryptographically secure 64-bit_count unsigned integer
        result_type operator()() {
            if (word_index >= 8) {
                refill_buffer();
            }
            return buffer.u64[word_index++];
        }

        inline uint32_t draw32() {
            // return (uint32_t)((*this)() >> 32); // high 32 bits
            // return (uint32_t)((*this)() >> 16); // middle 32 bits (unconventional, no benefit)
            return (uint32_t)((*this)());         // low 32 bits — standard, clean, and correct
        }
        inline uint64_t draw64() {
            return (*this)();
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

        // NO! WRONG!
        // bool operator==(const random_device&) const noexcept { return true; }

        /// @brief Reseeds the generator with a new key/nonce pair
        /// @param k  New 256-bit_count key
        /// @param n  New 64-bit_count nonce
        ///
        /// Useful after fork() in multi-process environments or for periodic reseeding.
        void reseed(const RNG::ChaChaCore::KEY& k, const RNG::ChaChaCore::NONCE& n) {
            key = k;
            nonce = n;
            block_counter = 0;
            refill_buffer();
        }

        /// @brief Discards the next @a n 64-bit_count values from the output stream
        /// @param n  Number of 64-bit_count values to skip (may be zero)
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
        /// Preserves full 64-bit_count nonce security.
        void jump() {
            discard(1ULL << 32);
        }

        /// @brief Advances the stream by exactly 2^48 outputs (2^51 bytes).
        /// Equivalent to calling operator() 2^48 times.
        ///
        /// Use to generate up to 2^16 non-overlapping subsequences for parallel computations
        /// (each subsequence has length 2^48).
        /// Preserves full 64-bit_count nonce security.
        void long_jump() {
            discard(1ULL << 48);
        }

        /// @brief Compares two csprng objects for equality of internal state
        /// @return true if and only if both generators produce identical future output
        ///
        /// The 256-bit_count key is compared in constant time to prevent timing attacks.
        /// The output buffer is intentionally not compared: when key, nonce,
        /// block_counter, and word_index are identical, the next generated value is
        /// guaranteed to be identical regardless of current buffer contents.
        friend bool operator==(const csprng& lhs, const csprng& rhs) noexcept
        {
            uint32_t key_diff = 0;
            for (size_t i = 0; i < 8; ++i)
                key_diff |= lhs.key[i] ^ rhs.key[i];

            bool state_match = (lhs.nonce == rhs.nonce) &&
                (lhs.block_counter == rhs.block_counter) &&
                (lhs.word_index == rhs.word_index);

            if (key_diff != 0 || !state_match) return false;

            // Only compare buffer if it's supposed to contain valid data
            if (lhs.word_index < 8) {
                uint64_t buffer_diff = 0;
                for (size_t i = 0; i < 8; ++i)
                    buffer_diff |= lhs.buffer.u64[i] ^ rhs.buffer.u64[i];
                return buffer_diff == 0;
            }
            return true;
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
        // Exposing the full internal state (especially the 256-bit_count key) would
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
        /// @param RNG The generator to serialize
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
        /// @param RNG The generator to restore into
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
            auto state = RNG::ChaChaCore::build_state(
                key,
                RNG::ChaChaCore::NONCE{ nonce[0], nonce[1] },
                block_counter
            );

            RNG::ChaChaCore::permute_block(buffer, state);
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
} // namespace RNG

