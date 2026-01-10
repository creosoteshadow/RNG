# RNG Collection

A set of high-quality, header-only C++ pseudorandom number generators.

**IMPORTANT DISCLAIMER**

        All generators in this repository are NON-CRYPTGRAPHIC PRNGs.
        
        They are designed for statistical quality, speed, and convenience in simulations, games, Monte-Carlo methods, 
        procedural generation, and other non-security applications.
        
        They are NOT suitable for any cryptographic purpose (key generation, nonces, gambling, security tokens, etc.).  
        They do NOT provide forward/backward secrecy or resistance to state compromise/observation.
        
        For cryptographic needs, use established secure primitives such as ChaCha20, AES-CTR, or platform APIs 
        (`std::random_device`, `/dev/urandom`, CryptGenRandom, etc.).

# Example Usage
        #include "RNG.h"
        
        int main() {
        	RNG::SplitMix64 sm(12345ull);
        	RNG::random_device rd;
        	RNG::wyrand wy(12345ull);
        	RNG::fast fa(12345ull);
        	RNG::Nasam1024 na(12345ull);
        
        	std::cout << "sm() = " << sm() << "\n";
        	std::cout << "rd() = " << rd() << "\n";
        	std::cout << "wy() = " << wy() << "\n";
        	std::cout << "fa() = " << fa() << "\n";
        	std::cout << "na() = " << na() << "\n";
        }
        
        /*
        Output Example. All outputs are deterministic except for rd.
        
        sm() = 2454886589211414944
        rd() = 2725604342 // varies from run to run, uses platform entropy
        wy() = 11217614207554058483
        fa() = 7388524142211027955
        na() = 5118035197337003306
        */
        


### RNG::random_device
        #include "RNG_random_device.h"  

        Drop-in replacement for std::random_device. Guaranteed non-deterministic results.
        
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

### RNG::Nasam1024
        **High-quality, buffered, counter-based generator with enormous period**  
        - **Internal state**: 1024-bit additive counter  
        - **Theoretical period**: 2^1024
        - **Output**: 512 bits per step (8 × 64-bit values from upper half), each strongly mixed with NASAM  
        - **Speed**: ~1.6–2.0 GB/s on modern x86-64  
        - **Quality**: PractRand clean through at least 64 GB (more extensive testing ongoing)  
        - **Best for**: Applications that demand the longest possible period, excellent statistical behavior, and easy parallel 
          stream splitting  

        **Note on period**: Although only 512 bits are output per step, the underlying 1024-bit counter with a coprime 
        increment guarantees a full 2¹⁰²⁴ cycle — one of the longest periods available in any non-cryptographic PRNG.
        
        When to choose Nasam1024  
                → You want a "set it and forget it" high-confidence generator with period far beyond any conceivable practical need  
                → You value the ability to create millions of uncorrelated streams with confidence they won't overlap

# Recommendation
    
General purpose: use RNG::Nasam1024. It is fast enough (unless you REALLY need more than 100 million random draws per second), 
has excellent quality (passes 64 GB Practrand), and is versatile. It has an internal state of 1024 bits, operates in "counter 
mode", uses a variant of the very strong NASAM mixer, and has very flexible jump operations.

Fastest possible: use rng::fast in Bulk mode.

True randomness: RNG::random_device. Uses system entropy.

# License
    MIT
