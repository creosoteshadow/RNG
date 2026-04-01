# RNG Collection

A small, high-quality collection of non-cryptographic pseudo-random number generators (PRNGs) in C++.
All have been tested and passed PractRand at 128 GB.

Contents

- **Random Number Generator Classes**
  - `class wyrand`
  - `class wy256`
  - `class SplitMix64`
  - `class xoshiro256plusplus`

- **Utility Functions**
  - `uint64_t mul128(uint64_t a, uint64_t b, uint64_t& hi)` - portable fast 64x64 -> 128 multiply
  - `uint64_t mix_fold(uint64_t a, uint64_t b)` - rapid-hash-style mixing function
  - `uint64_t mix_fold_protected(uint64_t a, uint64_t b)` - rapid-hash-style mixing function
  - `uint64_t mix_fold_protected_modified(uint64_t a, uint64_t b)` - rapid-hash-style mixing function
  - `uint8_t add_carry(uint8_t c, uint64_t a, uint64_t b, uint64_t* out)` - portable add_carry function
  - `uint64_t nasam(uint64_t x)` - Pelle Evensen's NASAM mixer
  - `uint64_t pelican(uint64_t state)` - Pelican mixing function
  - `uint64_t mx3(uint64_t x)` – John Maiga's mixing function.
  - `uint64_t better_rand_device()` – Improvement of rand_device, used to create random seeds.

## Usage

```cpp
#include "RNG.h"
#include <iostream>
int main() {
    uint64_t seed = RNG::Primitives::better_rand_device();
    RNG::SplitMix64 seeder(seed);
    RNG::wyrand wyrand_gen(seeder());
    RNG::wy256 wy256_gen(seeder());
    RNG::xoshiro256plusplus xoshiro_gen(seeder());

    // Advance 2^35 steps forward in the wy256 sequence.
    // This also works with RNG::SplitMix64 and RNG::wyrand.
    // See also the jump() and long_jump() functions in each class.
    wy256_gen.discard(1ull << 35);

    std::cout << "wyrand_gen() = " << wyrand_gen() << "\n";
    std::cout << "wy256_gen() = " << wy256_gen() << "\n";
    std::cout << "xoshiro_gen() = " << xoshiro_gen() << "\n";

    // Create 1024 instances of the xoshiro256plusplus generator, placing them in a vector.
    // Each generator is initialized with the same seed, but separated with a call to long_jump()
    // to ensure they provide independent streams of random numbers.
    seed = 123456789;
    size_t n_generators = 1024;
    auto generators = RNG::xoshiro256plusplus::factory(n_generators, seed);
}
```
## Discard and Jump Functions

The following routines are available for skipping forward in the sequence of random numbers.
All methods are O(1).

    - SplitMix64
		- discard(n) - equivalent to n calls to operator()
		- jump() - advance 2^32 steps
		- long_jump() - advance 2^48 steps
    - wyrand
		- discard(n) - equivalent to n calls to operator()
		- jump() - advance 2^32 steps
		- long_jump() - advance 2^48 steps
    - wy256
		- discard(n) - equivalent to n calls to operator()
		- jump() - advance 2^128 steps
		- long_jump() - advance 2^192 steps

    - xoshiro256plusplus
		- Note: no arbitrary discard(n) function
		- jump() - advance 2^128 steps
		- long_jump() - advance 2^192 steps


## Random Number Generation Functions

All generator classes include the following methods for generating random numbers.

		- operator()(): Returns the next random number in the sequence.
		- draw64(): Alias for operator()(), returns a 64 bit random number.
		- draw32(): Returns the upper 32 bits of the next random number.
		- uni(): Returns a double in the range [0.0, 1.0) using IEEE 754 bit manipulation for maximum performance.
		- uniform(u64 limit): returns an unbiased random number in the range [0, limit) using rejection sampling.
		- uniform(u64 lo, u64 hi): returns an unbiased random number in the range [lo, hi].

## Requirements

C++20 or later
x86/x64 for __rdtsc() (the current implementation)
<chrono>, <atomic>, <random>, and x86 intrinsics (<x86intrin.h> or <intrin.h>)

## Portability Note
An effort has been made to make this at least somewhat portable. Comments/suggestions welcome.

## Installation
Just drop the header files into your project. No external dependencies beyond the standard library and intrinsics.

## License
MIT

## Contributing
Suggestions for:

  - Better mixing strategies
  - Portable fallbacks (ARM, PowerPC, etc.)
  - Integration helpers for popular PRNGs
  - Benchmarks

are welcome!
