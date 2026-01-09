# RNG Collection

A set of high-quality, header-only C++ pseudorandom number generators.

**IMPORTANT DISCLAIMER**

**All generators in this repository are NON-CRYPTGRAPHIC PRNGs.**

They are designed for statistical quality, speed, and convenience in simulations, games, Monte-Carlo methods, procedural generation, and other non-security applications.

**They are NOT suitable for any cryptographic purpose** (key generation, nonces, gambling, security tokens, etc.).  
They do **not** provide forward/backward secrecy or resistance to state compromise/observation.

For cryptographic needs, use established secure primitives such as ChaCha20, AES-CTR, or platform APIs (`std::random_device`, `/dev/urandom`, CryptGenRandom, etc.).

### RNG::random_device
    #include "RNG_random_device.h"  

    Platform entropy source (non-deterministic) — ~0.06 GB/s (OS-limited)
    
    Uses function RNG_platform::get_entropy which is contained in file platform_entropy.cpp.

### RNG::SplitMix64
    #include "RNG_SplitMix64.h"     
    
    This is the classic fast seeder. > 5 GB/s
    
### RNG::wyrand
    #include "RNG_wyrand.h"
    
    Lightweight wyrand class. ~5 GB/s.
    
### RNG::fast
    #include "RNG_fast.h"
    
    High-performance wyrand variant
        Single-call: ~5.35 GB/s
        Bulk mode:    ~8.77 GB/s

### RNG::Nasam512
    #include "RNG_Nasam512.h"
    
    1024 bit state, 2^512 length period.
    
    Uses modified NASAM mixing.
    
    > 1 GB/s
    
    Passes PractRand at 64 GB.

# Recommendation
    
General purpose: use RNG::Nasam512. It is fast enough (unless you REALLY need more than 100 million random draws per second), has excellent quality (passes 64 GB Practrand), and is versatile. It has an internal state of 1024 bits, operates in "counter mode", uses a variant of the very strong NASAM mixer, and has very flexible jump operations.

Fastest possible: use rng::fast in Bulk mode.

True randomness: RNG::random_device. Uses system entropy.

# License
    MIT
