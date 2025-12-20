#pragma once
// file RNG_test.h
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <cstdint>
#include <string>
#include <chrono>

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

template <class GENERATOR>
inline void write_PractRand_file(int nGB, GENERATOR& gen) {
    //
    // Warning!! This function assumes RNG_test.exe is in the current directory.
    //

    if (nGB == 0 || nGB > 1024) {
        throw std::runtime_error("nGB must be between 1 and 1024");
    }

    constexpr size_t buffer_size = 64;
    u64 buffer[buffer_size];

    FILE* outfile = fopen("test.bin", "wb");
    if (!outfile) {
        printf("Error opening test.bin\n");
        system("pause");
        exit(EXIT_FAILURE);
    }

    u64 nwords = nGB * 1024ull * 1024ull * 1024ull / 8;
    std::cout << "Size: " << nGB << " GB\n";
    std::cout << "Words: " << nwords << "\n";

    u64 offset = 0;
    size_t remaining = nwords;
    while (remaining) {
        size_t n_used = std::min(remaining, buffer_size);
        for (size_t i = 0; i < n_used; i++)
            buffer[i] = gen.draw64();

        size_t nb = fwrite(buffer, sizeof(u64), n_used, outfile);
        if (nb < n_used) {
            printf("Error writing to test.bin at offset=%llu\n", offset);
            system("pause");
            fclose(outfile);
            exit(EXIT_FAILURE);
        }
        remaining -= n_used;
        offset += n_used;
        if (offset % (1024ull * 1024ull * 1024ull / 8) == 0) {
            std::cout << "Wrote " << (offset * 8) / (1024ull * 1024ull * 1024ull) << " GB\n";
        }
    }

    fflush(outfile);
    fclose(outfile);

    // Construct and execute PractRand command
    std::string command = "type test.bin | RNG_test.exe stdin64 -tf 2 -te 1 -tlmax " + std::to_string(nGB) + "GB -multithreaded";
    std::cout << "Executing PractRand command: " << command << "\n";
    int result = system(command.c_str());
    if (result != 0) {
        std::cerr << "PractRand command failed with return code " << result << "\n";
        system("pause");
        // Optionally exit or handle the error differently
    }
    else {
        std::cout << "PractRand command completed successfully\n";
    }

    //printf("Suggested PractRand command line (for reference):\n");
    //printf("\tWindows: %s\n", command.c_str());
    //printf("\tUnix: cat test.bin | ./RNG_test stdin64 -tf 2 -te 1 -tlmax %dGB -multithreaded\n", nGB);
}



template <class GENERATOR>
inline void speed_test(GENERATOR& gen, int nMB)
{
    // Nbytes is the total number of bytes
    uint64_t Nbytes = nMB * 1024 * 1024;
    uint64_t Ndraws = Nbytes / 8;

    uint64_t result = 0;

    auto start = std::chrono::high_resolution_clock::now();

    for (uint64_t i = 0; i < Ndraws; ++i) {
        result ^= gen.draw64(); // 8 bytes
    }

    auto finish = std::chrono::high_resolution_clock::now();

    if (result == 0)
        std::cout << "Unexpected value (anti-optimization).\n";

    // Calculate the difference between the two time_points.
    auto duration = finish - start;

    double elapsed = std::chrono::duration<double>(duration).count();

    double total_bytes = (double)Nbytes; 
    double GBPS = (total_bytes / (1024. * 1024. * 1024.)) / elapsed;

    std::cout << "Elapsed time (s) = " << elapsed << "\n";
    std::cout << "GBPS = " << GBPS << "\n";
}

#include "RNG.h"
inline void test_rng_generators() {
    rng::random_device gen1;
    rng::csprng        gen2;
    rng::fast_RNG      gen3;

    std::cout << "\n\nTesting rng::random_device\n";
    speed_test(gen1, 111);
    write_PractRand_file(2, gen1);

    std::cout << "\n\nTesting rng::csprng\n";
    speed_test(gen2, 111);
    write_PractRand_file(2, gen2);

    std::cout << "\n\nTesting rng::fast_RNG\n";
    speed_test(gen3, 1000);
    write_PractRand_file(2, gen3);
}

/*
  Suggested main.cpp:
  
  #include "RNG.h"
  int main(){
    test_rng_generators();
  }
*/
