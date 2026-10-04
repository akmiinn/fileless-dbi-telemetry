/*
 * Copyright (C) 2007-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include "pin.H"
#include "config.h"
#include "utils.h"

using std::string;
using std::vector;

/* ===================================================================== */
// Command-line knobs (construction happens here, exactly once).
/* ===================================================================== */
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for MyPinTool output");

KNOB< BOOL > KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1",
                       "count instructions, basic blocks and threads in the application");

KNOB< BOOL > KnobFilter(KNOB_MODE_WRITEONCE, "pintool", "filter", "1",
                         "filter out heavy CLR/OS runtime noise from per-instruction instrumentation "
                         "(noise modules are still counted in aggregate, just not per-basic-block)");

KNOB< string > KnobNoiseModules(
    KNOB_MODE_WRITEONCE, "pintool", "noise_modules",
    "clr.dll,coreclr.dll,clrjit.dll,clrjit_win7_x64_x64.dll,mscorlib,mscorwks.dll,mscoree.dll,"
    "ntdll.dll,kernel32.dll,kernelbase.dll,combase.dll,ole32.dll,oleaut32.dll,rpcrt4.dll,"
    "ucrtbase.dll,msvcrt.dll,msvcp,"
    // Authenticode/catalog signature-verification infrastructure invoked by the CLR assembly
    // loader and OS module loader on every load -- volume scales with number of assemblies
    // loaded, not with script complexity (empirically ~47% of the "interesting" bucket in a
    // privesc recon run, ~40% of which is present even in a no-op script). Not script logic.
    "bcryptprimitives.dll,crypt32.dll,msasn1.dll,cryptsp.dll",
    "comma-separated, case-insensitive substrings of module names to treat as background noise");

KNOB< string > KnobTargetImage(KNOB_MODE_WRITEONCE, "pintool", "target_image", "powershell.exe",
                                "substring identifying the target host image; always fully instrumented "
                                "even if it also matches noise_modules");

KNOB< BOOL > KnobDumpModules(KNOB_MODE_WRITEONCE, "pintool", "dump_modules", "1",
                              "print a per-module instruction/basic-block breakdown at exit");

KNOB< BOOL > KnobLogImages(KNOB_MODE_WRITEONCE, "pintool", "log_images", "1",
                            "log image load/unload events with wall-clock timestamps "
                            "for correlation against Sysmon Event ID 7 / ETW");

KNOB< BOOL > KnobUnbackedAlerts(KNOB_MODE_WRITEONCE, "pintool", "unbacked_alerts", "1",
                                 "real-time alert (address, thread id, timestamp) whenever execution enters "
                                 "memory with no backing PE image (fileless/JIT code)");

KNOB< BOOL > KnobUnbackedAlertAll(
    KNOB_MODE_WRITEONCE, "pintool", "unbacked_alert_all", "0",
    "log every dynamic entry into unbacked memory instead of only the first time each 4KB page "
    "is seen (verbose -- use for short validation runs, not full workloads)");

KNOB< UINT32 > KnobUnbackedDumpBytes(
    KNOB_MODE_WRITEONCE, "pintool", "unbacked_dump_bytes", "32",
    "hex-dump this many bytes from the unbacked region on each first-seen alert (0 disables; "
    "use to distinguish real shellcode from CLR JIT-stub churn)");

KNOB< BOOL > KnobApiWatch(
    KNOB_MODE_WRITEONCE, "pintool", "api_watch", "1",
    "log VirtualAlloc/VirtualAllocEx/CreateThread/CreateRemoteThread calls whose caller address "
    "is unbacked memory -- behavioral timeline of a payload's own API usage. LoadLibrary* is "
    "deliberately NOT hooked -- see kWatchedApis comment in tracker.cpp for why.");

/* ===================================================================== */
// Constants.
/* ===================================================================== */
const ADDRINT kPageSize = 0x1000;

const char* kWatchedApis[]  = { "VirtualAlloc", "VirtualAllocEx", "CreateThread", "CreateRemoteThread" };
const size_t kNumWatchedApis = sizeof(kWatchedApis) / sizeof(kWatchedApis[0]);

/* ===================================================================== */
// Derived settings.
/* ===================================================================== */
vector< string > gNoiseTokens;
string           gTargetToken;
vector< string > gWatchedApiTokens;

void InitConfig()
{
    gNoiseTokens = SplitCsv(KnobNoiseModules.Value());
    gTargetToken = ToLower(KnobTargetImage.Value());
    for (size_t i = 0; i < kNumWatchedApis; i++) gWatchedApiTokens.push_back(ToLower(kWatchedApis[i]));
}
