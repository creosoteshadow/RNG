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
