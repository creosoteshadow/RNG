#pragma once
// file RNG.h
// 
// RNG library - main public header
// Include this one file to get access to all generators
//
// Performance notes (January 2026, Intel Core i7-9700 @ 3.0 GHz, Windows 11)
// Throughput measured generating 800 MiB of output per run, single thread pinned to one core.
// Results are averages across all 8 cores.

#define NOMINMAX

#include "RNG_random_device.h"  // Platform entropy source (non-deterministic) — ~0.062 GB/s (OS-limited)

#include "RNG_SplitMix64.h"     // Classic fast seeder — ~5.60 GB/s

#include "RNG_wyrand.h"         // Lightweight wyrand — ~5.15 GB/s

#include "RNG_fast.h"           // High-performance wyrand variant
                                //   Single-call: ~5.35 GB/s
                                //   Bulk mode:    ~8.77 GB/s

#include "RNG_Nasam1024.h"       // 1024-bit state, 2^1024 period, NASAM mixing
                                //   Single-call: ~1.58 GB/s
                                //   Bulk mode:   ~1.77 GB/s
