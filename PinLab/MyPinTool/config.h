/*
 * Copyright (C) 2007-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef MYPINTOOL_CONFIG_H
#define MYPINTOOL_CONFIG_H

#include "pin.H"
#include <string>
#include <vector>

/* ===================================================================== */
// Command-line knobs.
// Each KNOB<T> is CONSTRUCTED exactly once, in config.cpp (construction
// registers it with Pin's command-line parser) -- every other file only
// ever sees the `extern` declaration below.
/* ===================================================================== */
extern KNOB< std::string > KnobOutputFile;
extern KNOB< BOOL >        KnobCount;
extern KNOB< BOOL >        KnobFilter;
extern KNOB< std::string > KnobNoiseModules;
extern KNOB< std::string > KnobTargetImage;
extern KNOB< BOOL >        KnobDumpModules;
extern KNOB< BOOL >        KnobLogImages;
extern KNOB< BOOL >        KnobUnbackedAlerts;
extern KNOB< BOOL >        KnobUnbackedAlertAll;
extern KNOB< UINT32 >      KnobUnbackedDumpBytes;
extern KNOB< BOOL >        KnobApiWatch;

/* ===================================================================== */
// Constants.
/* ===================================================================== */
extern const ADDRINT kPageSize; // alert dedup granularity: one alert per newly-seen 4KB page

// Watched APIs for the "API call originating from unbacked memory" behavioral-timeline
// feature (see tracker.cpp). LoadLibraryA/W/ExA/ExW are deliberately NOT included -- see
// the comment above LogCallFromUnbacked in tracker.cpp for why.
extern const char* kWatchedApis[];
extern const size_t kNumWatchedApis;

/* ===================================================================== */
// Derived settings -- populated once from knob values by InitConfig().
// InitConfig() MUST be called after PIN_Init() returns (knob values are not
// available until the command line has been parsed) and before any
// instrumentation callback is registered.
/* ===================================================================== */
extern std::vector< std::string > gNoiseTokens;     // lowercased KnobNoiseModules tokens
extern std::string                gTargetToken;     // lowercased KnobTargetImage
extern std::vector< std::string > gWatchedApiTokens; // lowercased kWatchedApis

void InitConfig();

#endif // MYPINTOOL_CONFIG_H
