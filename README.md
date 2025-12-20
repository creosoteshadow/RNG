# RNG
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++20](https://img.shields.io/badge/C++-20-blue.svg)](https://en.cppreference.com/w/cpp/20)
[![Header-only](https://img.shields.io/badge/Style-Header%20Only-brightgreen)](https://en.wikipedia.org/wiki/Header-only)
[![PractRand Clean](https://img.shields.io/badge/PractRand-64%20GiB%20Clean-success)](https://github.com/creosoteshadow/RNG/blob/main/RNG_test_results_raw.txt)

## Contents
- [Features](#features)
- [Quick Start](#quick-start)
- [Classes Overview](#classes-overview)
- [Benchmarks and Statistical Testing](#benchmarks-and-statistical-testing)  <!-- if you have this section -->
- [Build & Usage](#build--usage)
- [Notes & Warnings](#notes--warnings)
- [References](#references)
- [License](#license)

rng – A Modern C++ Random Number Generator Suite  
A lightweight, header-only (with companion .cpp) C++20 library providing three high-quality random number generators:

  - rng::random_device – A standards-conforming drop-in replacement for std::random_device using the platform’s cryptographically secure entropy source.
  - rng::csprng – A fast, cryptographically secure PRNG based on ChaCha20 (original Bernstein layout).
  - rng::fast_RNG – An extremely fast non-cryptographic PRNG inspired by wyrand (passes PractRand with no anomalies up to 64 GiB).

Also includes convenient utilities for filling buffers with secure random bytes and safe type-punning via rng::Block.
Features

Cross-platform – Works on Windows (via BCryptGenRandom) and Unix-like systems (getrandom() → /dev/urandom fallback).
Modern C++20 – Uses std::span, std::byte, concepts, and constexpr where appropriate.
Secure by default – The CSPRNG provides full 256-bit security, backtracking resistance, and protection against key/nonce reuse.
No dependencies – Only the C++ standard library and platform headers.
Header-only convenience – All classes and utilities are in a single header; the .cpp file contains only the platform-specific entropy implementation.
Thoroughly commented – Extensive documentation in the code for future maintenance.

# Quick Start

    #include "RNG.h"
    #include <iostream>
    
    int main() {
        // 1. Cryptographically secure randomness
        rng::csprng secure;  // seeded from OS entropy
        std::cout << "Secure uint64: " << secure() << "\n";
    
        // Unbiased random int in [1, 6]
        std::cout << "Dice roll: " << secure.unbiased(1u, 6u) << "\n";
    
        // 2. Fast non-cryptographic randomness (e.g., simulations, games)
        rng::fast_RNG fast(12345ULL);
        std::cout << "Fast uint64: " << fast() << "\n";
    
        // 3. Fill a buffer with secure random bytes
        std::array<std::byte, 32> key;
        rng::get_random_bytes(key);
    
        // 4. Use as a drop-in for std::random_device
        rng::random_device rd;
        std::cout << "random_device compatible: " << rd() << "\n";
    }
# Classes Overview

rng::random_device

Conforms to the UniformRandomBitGenerator concept.
Returns 32-bit values (like std::random_device).
Throws on entropy failure (rare but critical).

rng::csprng

ChaCha20-based stream cipher in counter mode.
256-bit key, 64-bit nonce, 64-bit block counter (original DJB layout).
Multiple constructors: from explicit key/nonce, 32/64-byte seed material, OS entropy (default), or deterministic seed.
Rejection sampling for unbiased bounded integers.
Constant-time state comparison.
Move-only (copying forbidden for security).

rng::fast_RNG

Single 64-bit state, ~11 GB/s throughput.
Based on wyrand with slight mixing variation.
Passes PractRand to 64 GiB with no anomalies.
Full UniformRandomBitGenerator support including discard() and stream serialization.

Utilities

rng::helper::get_random_bytes(std::span<std::byte> – Fill arbitrary buffers with secure entropy.
rng::helper::Block<N> – Safe union for viewing fixed-size byte blocks as u8, u16, u32, or u64 arrays.

### Benchmarks and Statistical Testing

Tested on Windows 11, MSVC 2022, Intel Core i7-13700K (single thread).

| Generator            | Speed (GB/s) | PractRand (2 GB) | Notes |
|----------------------|--------------|------------------|-------|
| `rng::random_device` | ~0.06       | No anomalies    | Limited by OS entropy rate (BCryptGenRandom). Expected behavior. |
| `rng::csprng`        | ~0.52       | No anomalies    | Strong for software ChaCha20 (comparable implementations: 0.3–1.0 GB/s). |
| `rng::fast_RNG`      | ~10.7       | No anomalies    | Matches wyrand (~10–12 GB/s) while passing rigorous tests. Previously tested to 64 GiB clean. |

See `RNG_test.h` for the tester and `RNG_test_results*` files for raw/reproduced output.

# Build & Usage

    Bash git clone https://github.com/creosoteshadow/RNG.git  
    cd rng

Just include the files in your project.

Example with CMake:  
    add_library(rng STATIC RNG.cpp)  
    target_include_directories(rng PUBLIC .)  
    target_compile_features(rng PUBLIC cxx_std_20)  
    No external build steps required beyond compiling RNG.cpp alongside your code.  

# Notes & Warnings

- The ChaCha20 implementation uses the original Bernstein layout (64-bit nonce + 64-bit counter). This is not RFC 8439 compliant (which uses 96-bit nonce + 32-bit counter). Do not interoperate with TLS, WireGuard, or libsodium without adaptation.
- Serialization operators on csprng are private and intentionally undocumented in the public API — exposing the full state breaks security.

# References
Here are some high-quality external resources for background on the key algorithms and tools used in this library. These provide deeper reading on design, security, and testing.

- wyrand / wyhash (basis for rng::fast_RNG)  
    Official repository by Wang Yi: https://github.com/wangyi-fudan/wyhash  
    (Includes wyrand implementation, discussions on statistical quality, and PractRand results.)  

- ChaCha20 (basis for rng::csprng)  
    Original paper by Daniel J. Bernstein: "ChaCha, a variant of Salsa20" (2008)  
    https://cr.yp.to/chacha/chacha-20080128.pdf  
    Note: This library uses Bernstein's original layout (64-bit nonce + 64-bit counter). For the IETF-standard variant (96-bit nonce + 32-bit counter, used in TLS/WireGuard): RFC 8439 - ChaCha20 and Poly1305 for IETF Protocols https://datatracker.ietf.org/doc/html/rfc8439

- PractRand (statistical test suite used for validation)  
    PractRand homepage and source (original by Chris Doty-Humphrey): http://pracrand.sourceforge.net/  
    (Recommended for rigorous RNG testing; our results were generated with this suite.)

- Lemire's unbiased bounded integer method (used in unbiased() across all generators)  
    "Fast Random Integer Generation in an Interval" by Daniel Lemire (2018)  
    https://arxiv.org/abs/1805.10941  
    (Describes the nearly-divisionless rejection sampling technique for uniform ranges without bias.)

- Platform entropy sources
    Windows: BCryptGenRandom (Microsoft Docs)  
    https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandomLinux/Unix: getrandom(2) man page  
    https://man7.org/linux/man-pages/man2/getrandom.2.html

# License

  MIT License – feel free to use in any project, commercial or open-source.  
  Author  
  creosoteshadow – 2025

Enjoy fast, secure, and reliable randomness! 🚀
