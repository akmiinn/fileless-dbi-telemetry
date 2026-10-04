/*
 * Copyright (C) 2007-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef MYPINTOOL_TYPES_H
#define MYPINTOOL_TYPES_H

#include "pin.H"

// Per-module (or "[unbacked-jit]") dynamic execution stats.
// NOTE: counters are plain (non-atomic) UINT64s, matching Pin's own example tools'
// convention -- under multi-threaded targets this is a benign race (like-sized aligned
// increments), acceptable for approximate profiling counts. std::atomic is intentionally
// avoided: <atomic> collides with pin.H's compatibility headers under MSVC and fails to
// compile.
struct ModuleStats
{
    UINT64 insCount = 0;
    UINT64 bblCount = 0;
    bool isNoise    = false;
    bool isUnbacked = false;
};

#endif // MYPINTOOL_TYPES_H
