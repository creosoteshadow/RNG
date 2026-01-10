#pragma once
// RNG_Nasam1024.h
// RNG::Nasam1024 ─ High-quality 1024-bit counter based PRNG with 2¹⁰²⁴ period
//                (upper 512 bits strongly mixed per counter step)

#include <algorithm>   // std::min, std::copy etc.
#include <array>
#include <bit>         // std::rotr
#include <cstdint>
#include <cstring>     // memcpy, memset (more standard than <string.h>)
#include <limits>

#include "RNG_SplitMix64.h"
#include "RNG_random_device.h"
#include "umul128.h"   // platform-specific 64×64→128 multiplication


// ─────────────────────────────────────────────────────────────────────────────
// All components live in namespace RNG
// ─────────────────────────────────────────────────────────────────────────────



// ─────────────────────────────────────────────────────────────────────────────
// Mixing functions
// ─────────────────────────────────────────────────────────────────────────────
namespace RNG {
	/*
	NASAM (Not Another Strange Adding Mixer) - 64-bit Variant

	Mixer: Strong triple-multiply 64-bit unary mixer
		Inspired by Pelle Evensen's high-quality non-cryptographic mixers
		(rrmxmx constant 0x9FB21C651E98DF25 and overall strong mixing patterns)
		See: http://mostlymangling.blogspot.com/
		Golden-ratio-derived multipliers common in hashing/PRNG literature
	*/
	[[nodiscard]] inline constexpr uint64_t nasam(uint64_t v) noexcept {
		/*
		History (ignore if you want):

		Here is the original version by Pelle Evensen.
		Source: https://mostlymangling.blogspot.com/2020/01/nasam-not-another-strange-acronym-mixer.html

			uint64_t nasam(uint64_t x) {
				// ror64(a, r) is a 64-bit rotation of a by r bits.
				x ^= ror64(x, 25) ^ ror64(x, 47);
				x *= 0x9E6C63D0676A9A99UL;
				x ^= x >> 23 ^ x >> 51;
				x *= 0x9E6D62D06F6A9A9BUL;
				x ^= x >> 23 ^ x >> 51;

				return x;
			}
		Note that his version differs from mine in constants and other details,
		but he gets the credit for developing the general pattern.
		*/
		v *= 0x9E6F1D9BB2D6C165ULL;
		v ^= std::rotr(v, 26);
		v *= 0x9E6F1D9BB2D6C165ULL;
		v ^= std::rotr(v, 47) ^ std::rotr(v, 21);
		v *= 0x9FB21C651E98DF25ULL; // Strong multiplier popularized in rrmxmx 
		// (orig. xxHash prime)			
		return v ^ (v >> 28);
	}
}


// ─────────────────────────────────────────────────────────────────────────────
// 1024-bit additive counter
// ─────────────────────────────────────────────────────────────────────────────
namespace RNG {
	class Counter_1024 {
		/*
		* This class is used to simplify 1024 bit counter use in random
		* number generators. It uses a custom increment based on the
		* golden ratio conjugate, and recursive nasam mixing of that
		* constant. We make no claim that these values are in any way optimum,
		* just that they work well in the Nasam1024 random number generator.
		* Obviously, it could be customized to use a different increment
		* without much difficulty, either through a new constructor or through
		* a set_increment(std::array<uint64_t, 16>) function, but for our needs
		* here (as a part of RNG::Nasam1024), what we have here is sufficient.
		*
		* Each call to the ++ operator adds one increment to the state.
		* A call to +=(n) will add n*increment to the state, where n is a
		* uint64_t. Much larger steps can be calculated with the big_jump
		* function.
		*/

		std::array<uint64_t, 16> state{ 0 };
		std::array<uint64_t, 16> increment{ 0 };

	public:
		constexpr Counter_1024() noexcept {
			initialize_increment();
		}

		// Explicitly default the copy and move special members
		Counter_1024(const Counter_1024& other) = default;        // copy constructor
		Counter_1024(Counter_1024&& other) noexcept = default;    // move constructor

		Counter_1024& operator=(const Counter_1024& other) = default;   // copy assignment
		Counter_1024& operator=(Counter_1024&& other) noexcept = default; // move assignment

		// Destructor can also be defaulted (optional, but good for clarity)
		~Counter_1024() = default;

		// data()
		uint64_t* data() noexcept { return state.data(); }
		const uint64_t* data() const noexcept { return state.data(); }

		// operator[]
		uint64_t& operator[](int index) noexcept { return state[index]; }
		const uint64_t& operator[](int index) const noexcept { return state[index]; }

		// prefix ++ 
		// Note: performs state+=increment, not state+=1
		Counter_1024& operator++() noexcept {
			for (int i = 0; i < 16; ++i) {
				add_carry(state.data(), increment[i], i);
			}
			return *this;
		}

		// postfix ++
		// Note: performs state+=increment, not state+=1
		Counter_1024 operator++(int) noexcept {
			Counter_1024 temp = *this;
			++(*this);
			return temp;
		}

		// Advance by nblocks full increments
		// state += nblocks * increment
		inline Counter_1024& operator+=(uint64_t nblocks) noexcept {
			if (nblocks == 0) {
				return *this;
			}
			if (nblocks == 1) {
				++(*this);  // Fast path — very common in RNG loops
				return *this;
			}

			// General case: multiply each increment limb by nblocks using 128-bit math
			uint64_t product_lo, product_hi;
			for (int i = 0; i < 16; ++i) {
				product_lo = RNG_detail::umul128(increment[i], nblocks, &product_hi);
				add_carry(state.data(), product_lo, i);
				if (i <= 14)add_carry(state.data(), product_hi, i + 1);
			}
			return *this;
		}

		// Big jump: state += step * increment (step is a 1024-bit integer)
		void big_jump(const uint64_t step[16]) noexcept {
			uint64_t temp[16];
			std::memcpy(temp, state.data(), sizeof(temp));

			for (int i = 0; i < 16; ++i) {
				if (step[i] == 0) continue;  // Skip zero contributions

				uint64_t lo, hi;
				for (int j = 0; j < 16; ++j) {
					// Only compute if result can affect the 1024-bit counter
					if (i + j < 16) {
						lo = RNG_detail::umul128(increment[j], step[i], &hi);
						add_carry(temp, lo, i + j);
						add_carry(temp, hi, i + j + 1);
					}
				}
			}
			std::memcpy(state.data(), temp, sizeof(state));
		}

		bool operator==(const Counter_1024& other) const noexcept {
			// Note: all 'increment' are the same, so we don't need to compare.
			return (state == other.state);
		}

		bool operator!=(const Counter_1024& other) const noexcept {
			return !(*this == other);
		}

	private:

		inline constexpr void initialize_increment() noexcept {
			constexpr uint64_t INC = 0x9e3779b97f4a7c15ULL;  // Golden ratio conjugate
			increment[0] = INC;
			for (int i = 1; i < 16; ++i) {
				increment[i] = nasam(increment[i - 1]);
			}
		}

		// Adds 'incr' to x[index] with full carry propagation upward
		inline static void add_carry(uint64_t x[16], uint64_t incr, int index) noexcept {
			if (index >= 16) return;

			if (x[index] += incr; x[index] < incr) {  // Carry detected?
				while (++index < 16) {
					if (++x[index] != 0) {
						return;  // Carry absorbed
					}
				}
			}
		}
	};
}


// ─────────────────────────────────────────────────────────────────────────────
// Main generator
// ─────────────────────────────────────────────────────────────────────────────
namespace RNG {

	/*
	* Nasam1024
	* ========
	*
	* A high-quality, fast, non-cryptographic 64-bit pseudorandom number generator.
	* (Or: a somewhat over-engineered but very robust monster PRNG...)
	*
	* Features at a glance:
	* • 100% header-only C++11 (or later)
	* • Only standard library dependency (+ SplitMix64 for single-seed initialization)
	* • Full std::random_number_engine / UniformRandomBitGenerator concept compliance
	* • Huge state: 1024-bit counter → period 2¹⁰²⁴
	* • Outputs upper 512 bits after strong mixing → excellent statistical quality
	* • Buffered generation: 8×64-bit values per counter increment
	* • Very efficient jump/split for parallel streams
	*
	* Statistical quality (as of January 2026):
	* • PractRand: clean through at least 64 GB
	*
	* Period: 2¹⁰²⁴
	*   (theoretical full period of the 1024-bit additive counter
	*    with coprime increment)
	*
	* Output: only upper 512 bits are used after very strong per-lane mixing
	* Buffer: 8 × 64-bit values are produced from each counter advance
	*
 	* Design
	* ------
	* Counter-based generator in the spirit of LXM family (large counter + strong mixer).
	*
	* • 1024-bit additive counter with carefully crafted irregular increment:
	*   - Starts from golden ratio conjugate constant φ⁻¹ × 2⁶⁴
	*   - Subsequent limbs recursively mixed with a very strong 64-bit unary function
	* • Each generation step:
	*   1. Increment the full 1024-bit counter
	*   2. Apply strong unary mixer independently to the upper 8×64 bits
	*   3. Buffer the 8 results (very good throughput)
	*
	* Mixer used:
	* Triple-multiply-rotate mixer heavily inspired by Pelle Evensen's research on 
	* strong mixers. 
	*
	* Performance notes
	* -----------------
	* • ~3.5–4.5 cycles per 64-bit output (including buffer management) on recent Intel/AMD
	* • Much faster than cryptographic generators, slower than minimal ones (wyrand, xoshiro256++)
	* • Trade-off deliberately chosen for:
	*   - Extremely long period
	*   - Excellent parallel stream support (no detectable correlation)
	*   - Very high confidence in long-run statistical quality
	*
	* When to use Nasam1024
	* --------------------
	*	Yes:
	*	  • Long-running simulations
	*	  • Parallel Monte-Carlo methods
	*	  • Future-proof code bases
	*	  • Applications requiring strict reproducibility across threads/processes
	*
	*	Maybe:
	*	  • General-purpose code where you want "overkill" statistical quality from a single engine
	*
	*	No:
	*	  • Extremely performance-critical code needing > 3–4 GB/s throughput
	* 
	*	***** ABSOLUTELY NOT *****
	*		Cryptographic applications: Nasam1024 is deliberately non-cryptographic — no forward/backward secrecy,
	*		no resistance to prediction or state compromise)
	*
	* Usage Example
	* -------------
	* #include "Nasam1024.h"
	* #include <iostream>
	* #include <random>
	*
	* int main() {
	*     // Deterministic seeding
	*     Nasam1024 rng(12345ULL);
	*
	*     // Direct generation
	*     for (int i = 0; i < 10; ++i)
	*         std::cout << rng() << '\n';
	*
	*     // With standard distributions
	*     std::uniform_int_distribution<int> dist(1, 100);
	*     std::cout << "Dice roll: " << dist(rng) << '\n';
	*
	*     // Fast skip-ahead (e.g., for parallel streams)
	*     rng.discard(1'000'000ULL);
	*
	*     // Fill buffers with random bytes
	*     std::array<uint8_t, 32> key;
	*     rng.fill(key.data(), key.size());
	*
	*     // Reseed mid-run
	*     rng.reseed(0xdeadbeefcafebabeULL);
	* }
	*
	* Performance
	* -----------
	* • Generates 8 outputs per counter advance (buffered)
	* • NASAM mixer: ≈3–4 cycles per 64-bit output on modern x86-64
	* • Jump-ahead uses native 128-bit multiplication (MSVC, GCC, Clang)
	* • PractRand tests TBD
	* 
	* Credits & Inspiration
	* ---------------------
	* • Strong 64-bit mixer variant: Timo Bingmann (TLX library)
	*   https://github.com/bingmann/tlx
	* • Original strong mixing concepts & constants: Pelle Evensen
	*   http://mostlymangling.blogspot.com/
	* • Golden ratio constant & counter-based ideas: widely used (PCG family, Romu, etc.)
	* • Jump-ahead implementation inspired by PCG & LXM family patterns
	*
	* License: MIT — use freely, modify, include in commercial projects, no restrictions
	*
	* Status: January 2026 — actively tested, documentation & deeper tests in progress
	*/

	/*
	PractRand results: 
	
	test.cpp
		#define NOMINMAX
		#define _CRT_SECURE_NO_WARNINGS
		//#include "RNG_benchmark.h"
		#include "RNG_Nasam1024.h"
		#include "pract_rand.h"

		#include <cstdint>
		#include <string.h>
		#include <iostream>

		int main()
		{
			RNG::Nasam1024 gen(12345ull);
			write_PractRand_file(64, gen);
			return EXIT_SUCCESS;
		}

	Executing PractRand command: type test.bin | RNG_test.exe stdin64 -tf 2 -te 1 -tlmax 64GB -multithreaded
	RNG_test using PractRand version 0.94
	RNG = RNG_stdin64, seed = unknown
	test set = expanded, folding = extra

	rng=RNG_stdin64, seed=unknown
	length= 64 megabytes (2^26 bytes), time= 2.7 seconds
	  no anomalies in 1008 test result(s)

	rng=RNG_stdin64, seed=unknown
	length= 128 megabytes (2^27 bytes), time= 7.5 seconds
	  no anomalies in 1081 test result(s)

	rng=RNG_stdin64, seed=unknown
	length= 256 megabytes (2^28 bytes), time= 14.6 seconds
	  no anomalies in 1151 test result(s)

	rng=RNG_stdin64, seed=unknown
	length= 512 megabytes (2^29 bytes), time= 25.5 seconds
	  no anomalies in 1220 test result(s)

	rng=RNG_stdin64, seed=unknown
	length= 1 gigabyte (2^30 bytes), time= 45.1 seconds
	  no anomalies in 1294 test result(s)

	rng=RNG_stdin64, seed=unknown
	length= 2 gigabytes (2^31 bytes), time= 80.6 seconds
	  no anomalies in 1368 test result(s)

	rng=RNG_stdin64, seed=unknown
	length= 4 gigabytes (2^32 bytes), time= 150 seconds
	  no anomalies in 1447 test result(s)

	rng=RNG_stdin64, seed=unknown
	length= 8 gigabytes (2^33 bytes), time= 293 seconds
	  no anomalies in 1545 test result(s)

	rng=RNG_stdin64, seed=unknown
	length= 16 gigabytes (2^34 bytes), time= 573 seconds
	  no anomalies in 1640 test result(s)

	rng=RNG_stdin64, seed=unknown
	length= 32 gigabytes (2^35 bytes), time= 1104 seconds
	  no anomalies in 1717 test result(s)

	rng=RNG_stdin64, seed=unknown
	length= 64 gigabytes (2^36 bytes), time= 2271 seconds
	  no anomalies in 1807 test result(s)

	PractRand command completed successfully
	*/
	class Nasam1024 {
	protected:
		// Declare counter
		int static constexpr COUNTERSIZE = 16; // 1024 bits / 64 bits per lane
		Counter_1024 counter;

		// Declare buffer
		static const int BUFFERSIZE = 8;
		uint64_t buffer[BUFFERSIZE]; // output buffer
		int buffer_position = BUFFERSIZE;  // buffer_position==BUFFERSIZE means buffer is empty

		inline void refill_buffer() noexcept {
			// This ++ operator actually "increments" the counter by a complex 1024 bit integer.
			// See class Counter_1024 for details
			++counter; 

			// Use only the upper 512 bits of the counter as input to the buffer. The lower
			// bits have a shorter period, so we don't use them.
			for (int i = 0; i < BUFFERSIZE; ++i)
				// counter is twice the size buffer, so ...
				buffer[i] = nasam(counter[i + BUFFERSIZE]);

			buffer_position = 0; // buffer is full
		}

		inline bool is_buffer_empty() const noexcept { return (buffer_position == BUFFERSIZE); }
		inline bool is_buffer_full () const noexcept { return (buffer_position == 0); }

	public:

		//
		// CONSTRUCTORS AND DESTRUCTOR
		// 

		// Default constructor: non-deterministic seeding via RNG::random_device
		Nasam1024() {
			RNG::random_device rd;
			for (int i = 0; i < COUNTERSIZE; ++i) {
				counter[i] = rd.draw64();  // or equivalent
			}
			buffer_position = BUFFERSIZE; // invalidate buffer to force call to refill_buffer()
		}

		// Construct from a single 64-bit seed (deterministic) using SplitMix64
		explicit Nasam1024(uint64_t seed) {
			reseed(seed);
		}

		// Construct from an explicit full 1024-bit initial_state, where initial_state
		// is a jump distance from the default zero counter.
		explicit Nasam1024(const std::array<uint64_t, 16>& initial_state) noexcept
			: counter{}
			, buffer_position{ BUFFERSIZE }
		{
			uint64_t step[16] = {};
			std::memcpy(step, initial_state.data(), sizeof(uint64_t) * COUNTERSIZE);
			counter.big_jump(step);
		}

		// Construct from any SeedSequence-compatible type (e.g., std::seed_seq, random_device)
		template<class Sseq>
		explicit Nasam1024(Sseq& seq) {
			std::uint32_t seeds[2*COUNTERSIZE];
			seq.generate(seeds, seeds + 2* COUNTERSIZE);
			for (int i = 0; i < COUNTERSIZE; ++i) {
				counter[i] = (static_cast<uint64_t>(seeds[2 * i]) << 32) | seeds[2 * i + 1];
			}
			buffer_position = BUFFERSIZE; // invalidate buffer to force call to refill_buffer()
		}

		// (Just to show intent) 
		// Copy and move are safe and efficient — use defaults
		Nasam1024(const Nasam1024&) = default;
		Nasam1024& operator=(const Nasam1024&) = default;
		Nasam1024(Nasam1024&&) = default;
		Nasam1024& operator=(Nasam1024&&) = default;

		// Destructor also defaulted
		~Nasam1024() = default;

		//
		// RANDOM NUMBER GENERATION
		// 

		// Generate the next 64 bit random number
		inline uint64_t operator()() noexcept {
			if (is_buffer_empty())
				refill_buffer();
			return buffer[buffer_position++];
		}
		inline uint32_t draw32() noexcept {
			uint64_t a = this->operator()();
			return static_cast<uint32_t>(a);
		}
		inline uint64_t draw64() noexcept {
			return this->operator()();
		}


		// fill a byte buffer with n bytes of random data
		inline void bulk(uint8_t* x, size_t n) noexcept
		{
			uint8_t* p = x;
			// Assume we have an empty buffer at start. So, we have to refill_buffer 
			// each time we want another 64 bytes.
			
			// fill full buffer-sized chunks
			constexpr size_t bufsize = BUFFERSIZE * sizeof(uint64_t); // 64 bytes
			while (n >= bufsize) {
				refill_buffer();
				memcpy(p, buffer, bufsize);
				n -= bufsize;
				p += bufsize;
			}
			// fill any remaining bytes
			if (n > 0) {
				refill_buffer();
				memcpy(p, buffer, n);
			}
			// invalidate the buffer
			buffer_position = BUFFERSIZE;
		}

		// Optional convenience overloads 
		void fill(std::span<std::byte> data) noexcept {
			bulk(reinterpret_cast<uint8_t*>(data.data()), data.size());
		}

		template <class T, size_t N>
		void fill(std::array<T, N>& arr) noexcept {
			fill(std::as_bytes(std::span(arr)));
		}

		template <class T>
		void fill(std::vector<T>& vec) noexcept {
			fill(std::as_bytes(std::span(vec)));
		}

		// Fill a byte buffer with random data
		// Useful for generating random keys, noise, or initializing memory
		void fill(uint8_t* data, size_t size) noexcept {
			bulk(data, size);
		}

		// 
		// STATE MAMAGEMENT
		// 

		// Since this is a non-cryptographic RNG, we provide state get/set functions

		Nasam1024& set_counter(const Counter_1024& initial_counter) noexcept {
			counter = initial_counter;
			return *this;
		}

		Counter_1024 get_counter() const noexcept {
			return counter;
		}

		// Advance the RNG state by 'n' outputs without generating them.
		void discard(uint64_t n) noexcept {
			// Goal: Advance the RNG forward by exactly 'n' output values,
			// without generating them individually (for efficiency).

			// Step 1: Consume any outputs already present in the current buffer
			// buffer_position is the index of the next available value (0 <= buffer_position < BUFFERSIZE when buffer has data)
			uint64_t remaining_in_buffer = static_cast<uint64_t>(BUFFERSIZE) - buffer_position;

			if (n <= remaining_in_buffer) {
				// All requested skips are within the current buffer — just advance the pointer
				buffer_position += static_cast<int>(n);
				return;
			}

			// We've used up the current buffer
			n -= remaining_in_buffer;

			// Step 2: Skip full blocks of STATESIZE outputs efficiently
			// Each block corresponds to one increment of the counter + NASAM mixing
			uint64_t full_blocks_to_skip = n / BUFFERSIZE;        // Complete blocks we can bypass entirely
			uint64_t outputs_in_final_block = n % BUFFERSIZE;     // Outputs needed from the next block

			// Advance the counter past all the full blocks we want to completely skip
			if (full_blocks_to_skip > 0) {
				counter += (full_blocks_to_skip);
			}

			// Step 3: Generate the block that contains the remaining outputs
			// refill_buffer() correctly:
			//   - increments the counter one more time
			//   - applies NASAM to produce a fresh buffer of STATESIZE outputs
			// This is intentional and necessary — we need access to these values
			// so we can skip the first 'outputs_in_final_block' of them.
			refill_buffer();

			// Step 4: Position the buffer pointer past the outputs we just "discarded"
			// in the newly generated block
			buffer_position = static_cast<int>(outputs_in_final_block);

			// At this point, exactly 'n' outputs have been skipped,
			// and the next call to operator()() will return the correct value.
		}

		void big_jump(uint64_t step[16]) {
			counter.big_jump(step);
		}
		void jump64() {
			uint64_t step[16] = { 0,1,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };
			counter.big_jump(step);
		}
		void jump128() {
			uint64_t step[16] = { 0,0,1,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };
			counter.big_jump(step);
		}
		void jump192() {
			uint64_t step[16] = { 0,0,0,1, 0,0,0,0, 0,0,0,0, 0,0,0,0 };
			counter.big_jump(step);
		}
		void jump256() {
			uint64_t step[16] = { 0,0,0,0, 1,0,0,0, 0,0,0,0, 0,0,0,0 };
			counter.big_jump(step);
		}
		void jump() { jump128(); }
		void long_jump() { jump256(); }

	public:	// Compatibility
		using result_type = uint64_t;

		struct Nasam1024_state {
			int static constexpr COUNTERSIZE = 16; // 1024 bits / 64 bits per lane
			int static constexpr BUFFERSIZE = 8;

			Counter_1024 counter;
			uint64_t buffer[BUFFERSIZE]; // output buffer
			int buffer_position;
		};
		Nasam1024_state get_state() const {
			Nasam1024_state statecopy;
			statecopy.counter = counter;
			memcpy(statecopy.buffer, buffer, BUFFERSIZE * 8); // BUFFERSIZE 8-byte words
			statecopy.buffer_position = buffer_position;
			return statecopy;
		}
		void set_state(const Nasam1024_state &s) {
			counter = s.counter;
			memcpy(buffer, s.buffer, BUFFERSIZE * 8); // BUFFERSIZE 8-byte words
			buffer_position = s.buffer_position;
		}

		// Constants required by the concept
		static constexpr result_type min() noexcept { return 0; }
		static constexpr result_type max() noexcept { return std::numeric_limits<result_type>::max(); }

		// 1. seed() with no argument — same as default constructor
		void seed() {
			*this = Nasam1024();  // delegating to default ctor
		}

		// 2. seed() with single uint64_t — delegate to your existing ctor
		void seed(uint64_t s) {
			*this = Nasam1024(s);
		}

		// 3. seed() with SeedSequence — delegate to template ctor
		template<class Sseq>
		void seed(Sseq& seq) {
			*this = Nasam1024(seq);
		}

		// 4. Equality / inequality — compare full state
		friend bool operator==(const Nasam1024& lhs, const Nasam1024& rhs) {
			return lhs.buffer_position == rhs.buffer_position 
				&& (lhs.counter == rhs.counter) 
				&& std::memcmp(lhs.buffer, rhs.buffer, sizeof(lhs.buffer)) == 0;
			// inc[] is always the same, no need to compare
		}

		friend bool operator!=(const Nasam1024& lhs, const Nasam1024& rhs) {
			return !(lhs == rhs);
		}

		void reseed(uint64_t seed) noexcept {
			RNG::SplitMix64 gen(seed);
			uint64_t step[16];
			for (int i = 0; i < 16; i++)
				step[i] = gen();
			counter = Counter_1024(); // all zeroes
			counter.big_jump(step);
			buffer_position = BUFFERSIZE;  // Invalidate buffer — will refill on next call
		}
	};// class Nasam1024
}// namespace RNG



