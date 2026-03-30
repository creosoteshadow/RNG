# RNG Collection

A small, high-quality collection of non-cryptographic pseudo-random number generators (PRNGs) in C++.

Contents

- **Functions**
  - `uint64_t mx3(uint64_t x)` – John Maiga's mixing function.
  - `uint64_t better_rand_device()` – Improved random seed generator.

- **Random Number Generator Classes**
  - `class wyrand`
  - `class wy256`
  - `class SplitMix64`
  - `class xoshiro256plusplus`

## uint64_t mx3(uint64_t x)

A modern multiply-xor mixing function by John Maiga with very high quality avalanche properties.

## uint64_t better_rand_device() 

`std::random_device` is the standard way to obtain entropy in C++, but it has well-known issues:

- On some platforms and older implementations (especially MinGW/GCC on Windows), it can be **deterministic** or have very low entropy, leading to identical random sequences on every program run.
- Even on good platforms, a single call may not provide enough mixing or uniqueness when used directly.
- This utility addresses those problems by combining multiple independent sources of jitter and entropy, then mixing them with a strong avalanche function.

## class wyrand 

A Weyl-Mix RNG. A c++ class that encapsulates the extremely fast, high quality 64 bit RNG by Wang Yi.

## class wy256

Weyl-Mix RNG. A cousin of wyrand - 256 bit state, uses wyrand mixing function, with 2^256 period and strong streaming support.

## class SplitMix64

LCG/Permuted RNG. The classic 64 bit RNG.

User Interface

	// Construct, destruct, seed
	constexpr SplitMix64(u64 seed);
	SplitMix64()noexcept;
	SplitMix64(const SplitMix64& other);
	SplitMix64(SplitMix64&& other);

	// Random number generation
	u64 operator()(); --return 64 bit random value
	u64 draw64(); --return 64 bit random value
	uint32_t draw32(); --return 32 bit random value
	inline double uni(); -- Return a uniformly distributed double in the range [0.0, 1.0)
	u64 uniform(u64 limit);	     -- Return in range [0,limit)
	u64 uniform(u64 lo, u64 hi); -- Return in range [lo,hi]

	// jump functions
	constexpr inline SplitMix64& discard(u64 nsteps); -- discard an arbitrary number of steps
	constexpr inline SplitMix64& jump()noexcept;	  -- jump, 2^32 steps
	constexpr inline SplitMix64& long_jump()noexcept; --  long_jump, 2^48 steps

	// seeding
	constexpr inline SplitMix64& reseed(u64 seed)noexcept; -- reseed the generator. Resets the state.

	// Multi-stream support

	// Returns a vector of n independent SplitMix64 generators, each initialized with the
	// same seed but separated by 2^48 steps using long_jump(). This allows for up to 2^16 
	// independent streams with a 2^48 step separation, which is a safe distance for most 
	// applications. For more extreme separation, consider using wy128 or wy256 with their 
	// 'big_jump' methods.
	static std::vector<SplitMix64> factory(size_t n, u64 initial_seed);

	// min and max
	static inline u64 min();
	static inline u64 max();

## class xoshiro256plusplus 

Shift-Register RNG. 2019 by David Blackman and Sebastiano Vigna - A high-quality 256 bit state NCPRNG.

## Usage

```cpp
#include "RNG.h" 

uint64_t seed = RNG::better_rand_device();
RNG::SplitMix64 seeder(seed);
RNG::wy256 wy1(seeder());
RNG::wy256 wy2(seeder());
RNG::wy256 wy3(seeder());
std::cout << "wy1() = " << wy1() << "\n";
std::cout << "wy2() = " << wy2() << "\n";
std::cout << "wy3() = " << wy3() << "\n";
```

## Requirements

C++11 or later
x86/x64 for __rdtsc() (the current implementation)
<chrono>, <atomic>, <random>, and x86 intrinsics (<x86intrin.h> or <intrin.h>)

## Portability Note
The current version relies on __rdtsc(). On non-x86 platforms it will need a fallback (e.g. extra clock calls or architecture-specific cycle counters). Pull requests for portable fallbacks are welcome.

## Installation
Just drop RNG.h into your project. No external dependencies beyond the standard library and intrinsics.

## License
MIT

## Contributing
Suggestions for:

  - Better mixing strategies
  - Portable fallbacks (ARM, PowerPC, etc.)
  - Integration helpers for popular PRNGs
  - Benchmarks

are welcome!
