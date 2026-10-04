/*
 * Copyright (C) 2007-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  Core tracking logic: module-aware noise filtering (RQ3), unbacked-memory execution
 *  alerting with byte-level payload dumping, and API-call-from-unbacked-memory behavioral
 *  timeline tracking (RQ5). See the design notes above LogCallFromUnbacked for a real
 *  debugging story worth keeping if this file is ever extended with more watched APIs.
 */

#include "pin.H"
#include "tracker.h"
#include "config.h"
#include "types.h"
#include "utils.h"

#include <iostream>
#include <fstream>
#include <map>
#include <set>

using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Tracker-internal state (file-scope / internal linkage -- nothing outside
// this translation unit touches these directly).
/* ================================================================== */

static UINT64 threadCount = 0; // total number of threads, including main thread

static std::ostream* out = &cerr;

static std::map< string, ModuleStats* > gModuleStats;
static PIN_LOCK gMapLock; // guards structural changes (insertion) to gModuleStats only

// Unbacked-memory (fileless) execution alerting state.
static PIN_LOCK gAlertLock;
static std::set< ADDRINT > gUnbackedPagesSeen;
static UINT64 gUnbackedAlertCount = 0;
static bool gHasFirstAlert        = false;
static ADDRINT gFirstAlertAddr    = 0;
static THREADID gFirstAlertTid    = 0;
static string gFirstAlertTs;

// API-from-unbacked-caller alerting state (behavioral timeline of a payload: what it
// calls, not just where its code sits).
static UINT64 gApiFromUnbackedCount = 0;

/* ===================================================================== */
// Internal helpers
/* ===================================================================== */

// Returns (and lazily creates) the stats bucket for a module key.
static ModuleStats* GetOrCreateStats(const string& key, bool isNoise, bool isUnbacked)
{
    PIN_GetLock(&gMapLock, 1);
    auto it = gModuleStats.find(key);
    ModuleStats* stats;
    if (it == gModuleStats.end())
    {
        stats             = new ModuleStats();
        stats->isNoise    = isNoise;
        stats->isUnbacked = isUnbacked;
        gModuleStats[key] = stats;
    }
    else
    {
        stats = it->second;
    }
    PIN_ReleaseLock(&gMapLock);
    return stats;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

// Exact, per-basic-block accounting for interesting code (target image + unbacked/JIT memory).
static VOID CountBbl(UINT32 numInstInBbl, ModuleStats* stats)
{
    stats->bblCount++;
    stats->insCount += numInstInBbl;
}

// Aggregate, per-trace accounting for noise modules: one call regardless of how many
// basic blocks the trace contains, to keep totals accurate without per-BBL overhead.
static VOID CountTraceAggregate(UINT32 numInstInTrace, UINT32 numBblInTrace, ModuleStats* stats)
{
    stats->bblCount += numBblInTrace;
    stats->insCount += numInstInTrace;
}

// Real-time fileless-execution alert: fires when control enters memory with no backing PE
// image. This is the DBI ground-truth event that Sysmon/ETW have no equivalent for -- neither
// exposes "code began executing from this non-image-backed address" at instruction granularity.
static VOID UnbackedAlert(ADDRINT insAddr, THREADID tid)
{
    string ts    = NowTimestamp();
    string bytes = HexDump(insAddr, KnobUnbackedDumpBytes.Value());

    PIN_GetLock(&gAlertLock, 1);
    gUnbackedAlertCount++;
    if (!gHasFirstAlert)
    {
        gHasFirstAlert  = true;
        gFirstAlertAddr = insAddr;
        gFirstAlertTid  = tid;
        gFirstAlertTs   = ts;
    }
    PIN_ReleaseLock(&gAlertLock);

    *out << "[" << ts << "] [ALERT] UNBACKED_EXEC addr=0x" << std::hex << insAddr << std::dec << " tid=" << tid;
    if (!bytes.empty()) *out << " bytes=[ " << bytes << "]";
    *out << endl;
}

// Behavioral-timeline alert: fires when a CALL instruction *inside unbacked memory* targets
// one of the watched APIs (memory allocation, thread creation) - i.e. the fileless code is
// actively driving further OS behavior, not just sitting there.
//
// Deliberately NOT implemented as a hook on the API's global entry point (e.g. RTN_FindByName
// + RTN_InsertCall on kernelbase!VirtualAlloc): that approach was tried and empirically broke
// the instrumented process. VirtualAlloc/CreateThread are hot-path APIs called constantly by
// the CLR's own GC/JIT/thread pool; hooking their global entry with a PIN_LockClient()-taking
// analysis routine caused the host process to die silently during CLR startup (confirmed via
// A/B test: with the hook, runs truncated to ~100-140M instructions and zero script output;
// without it, runs completed normally at 1.2B+ instructions). Instrumenting only CALL sites
// that occur within unbacked memory avoids this entirely -- that population is a tiny, bounded
// subset of the process's total instructions (never touches the hot global API entry point).
// kWatchedApis (config.cpp) deliberately excludes LoadLibraryA/W/ExA/ExW for the same reason:
// hooking the module loader itself is reentrant with Pin's own module-load instrumentation.
static VOID LogCallFromUnbacked(ADDRINT callerIp, ADDRINT targetAddr, ADDRINT rcx, ADDRINT rdx, THREADID tid)
{
    PIN_LockClient();
    RTN rtn = RTN_FindByAddress(targetAddr);
    string apiName;
    if (RTN_Valid(rtn)) apiName = RTN_Name(rtn);
    PIN_UnlockClient();

    if (apiName.empty()) return;
    if (!MatchesAnyToken(ToLower(apiName), gWatchedApiTokens)) return;

    string ts = NowTimestamp();
    PIN_GetLock(&gAlertLock, 1);
    gApiFromUnbackedCount++;
    PIN_ReleaseLock(&gAlertLock);

    *out << "[" << ts << "] [ALERT] API_FROM_UNBACKED api=" << apiName << " caller=0x" << std::hex << callerIp
         << " arg0=0x" << rcx << " arg1=0x" << rdx << std::dec << " tid=" << tid << endl;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID Trace(TRACE trace, VOID* v)
{
    ADDRINT addr = TRACE_Address(trace);
    IMG img      = IMG_FindByAddress(addr);

    string key;
    bool isUnbacked = false;
    bool isNoise    = false;

    if (IMG_Valid(img))
    {
        key            = IMG_Name(img);
        string base    = BaseName(key);
        string baseLow = ToLower(base);
        bool isTarget  = MatchesToken(baseLow, gTargetToken);
        isNoise        = KnobFilter && !isTarget && MatchesAnyToken(baseLow, gNoiseTokens);
    }
    else
    {
        key        = "[unbacked-jit]";
        isUnbacked = true;
        isNoise    = false; // never filter unbacked/JIT memory
    }

    ModuleStats* stats = GetOrCreateStats(key, isNoise, isUnbacked);

    if (isNoise)
    {
        // Single aggregate call for the whole trace instead of one call per basic block.
        UINT32 totalIns = 0;
        UINT32 numBbls  = 0;
        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
        {
            totalIns += BBL_NumIns(bbl);
            numBbls++;
        }
        BBL head = TRACE_BblHead(trace);
        if (BBL_Valid(head))
        {
            BBL_InsertCall(head, IPOINT_BEFORE, (AFUNPTR)CountTraceAggregate, IARG_UINT32, totalIns,
                           IARG_UINT32, numBbls, IARG_PTR, stats, IARG_END);
        }
        return;
    }

    // Interesting code: full per-basic-block fidelity.
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_PTR, stats,
                       IARG_END);
    }

    if (isUnbacked && KnobUnbackedAlerts)
    {
        bool shouldAlert = KnobUnbackedAlertAll;
        if (!shouldAlert)
        {
            // Dedup by 4KB page: alert once per newly-discovered unbacked code region rather than
            // on every dynamic entry, since JIT-compiled script bytecode re-enters the same stubs
            // constantly and would otherwise flood the log.
            ADDRINT page = addr & ~(kPageSize - 1);
            PIN_GetLock(&gAlertLock, 1);
            shouldAlert = gUnbackedPagesSeen.insert(page).second;
            PIN_ReleaseLock(&gAlertLock);
        }

        if (shouldAlert)
        {
            BBL head = TRACE_BblHead(trace);
            if (BBL_Valid(head))
            {
                BBL_InsertCall(head, IPOINT_BEFORE, (AFUNPTR)UnbackedAlert, IARG_INST_PTR, IARG_THREAD_ID,
                               IARG_END);
            }
        }
    }

    if (isUnbacked && KnobApiWatch)
    {
        // Instrument CALL instructions inside unbacked memory only (never the global API entry
        // point -- see LogCallFromUnbacked comment for why). IARG_BRANCH_TARGET_ADDR resolves
        // indirect calls (the common case for shellcode invoking an IAT/resolved pointer) at
        // runtime; RCX/RDX carry the first two args per the Windows x64 ABI.
        for (BBL bbl2 = TRACE_BblHead(trace); BBL_Valid(bbl2); bbl2 = BBL_Next(bbl2))
        {
            for (INS ins = BBL_InsHead(bbl2); INS_Valid(ins); ins = INS_Next(ins))
            {
                if (!INS_IsCall(ins)) continue;
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogCallFromUnbacked, IARG_INST_PTR,
                               IARG_BRANCH_TARGET_ADDR, IARG_REG_VALUE, REG_RCX, IARG_REG_VALUE, REG_RDX,
                               IARG_THREAD_ID, IARG_END);
            }
        }
    }
}

VOID ImageLoad(IMG img, VOID* v)
{
    if (!KnobLogImages) return;
    *out << "[" << NowTimestamp() << "] IMG_LOAD  " << IMG_Name(img) << " base=0x" << std::hex
         << IMG_LowAddress(img) << std::dec << " size=" << (IMG_HighAddress(img) - IMG_LowAddress(img) + 1)
         << endl;
}

VOID ImageUnload(IMG img, VOID* v)
{
    if (!KnobLogImages) return;
    *out << "[" << NowTimestamp() << "] IMG_UNLOAD " << IMG_Name(img) << endl;
}

VOID ThreadStart(THREADID threadIndex, CONTEXT* ctxt, INT32 flags, VOID* v)
{
    threadCount++;
    *out << "[" << NowTimestamp() << "] THREAD_START tid=" << threadIndex << endl;
}

VOID ThreadFini(THREADID threadIndex, const CONTEXT* ctxt, INT32 code, VOID* v)
{
    *out << "[" << NowTimestamp() << "] THREAD_END   tid=" << threadIndex << endl;
}

VOID Fini(INT32 code, VOID* v)
{
    UINT64 totalIns = 0, totalBbl = 0;
    UINT64 noiseIns = 0, noiseBbl = 0;
    UINT64 interestingIns = 0, interestingBbl = 0;
    UINT64 unbackedIns = 0, unbackedBbl = 0;

    for (auto& kv : gModuleStats)
    {
        UINT64 ins = kv.second->insCount;
        UINT64 bbl = kv.second->bblCount;
        totalIns += ins;
        totalBbl += bbl;
        if (kv.second->isNoise)
        {
            noiseIns += ins;
            noiseBbl += bbl;
        }
        else
        {
            interestingIns += ins;
            interestingBbl += bbl;
        }
        if (kv.second->isUnbacked)
        {
            unbackedIns += ins;
            unbackedBbl += bbl;
        }
    }

    UINT64 moduleBackedIns = interestingIns - unbackedIns; // "interesting" minus the unbacked-jit bucket
    UINT64 moduleBackedBbl = interestingBbl - unbackedBbl;

    *out << "===============================================" << endl;
    *out << "MyPinTool analysis results (filter=" << (KnobFilter ? "on" : "off") << "): " << endl;
    *out << "Total instructions:        " << totalIns << endl;
    *out << "Total basic blocks:        " << totalBbl << endl;
    *out << "Number of threads:         " << threadCount << endl;

    *out << "-----------------------------------------------" << endl;
    *out << "MODULE-BACKED EXECUTION (code backed by a PE image on disk):" << endl;
    *out << "  Noise (CLR/OS) instr.:      " << noiseIns << " (" << bbl_pct(noiseIns, totalIns) << "%)" << endl;
    *out << "  Interesting instr.:         " << moduleBackedIns << " (" << bbl_pct(moduleBackedIns, totalIns)
         << "%)" << endl;
    *out << "  Interesting basic blocks:   " << moduleBackedBbl << endl;

    *out << "-----------------------------------------------" << endl;
    *out << "FILELESS / UNBACKED EXECUTION:" << endl;
    *out << "  Unbacked instructions:      " << unbackedIns << " (" << bbl_pct(unbackedIns, totalIns) << "%)"
         << endl;
    *out << "  Unbacked basic blocks:      " << unbackedBbl << endl;
    *out << "  Distinct unbacked pages:    " << gUnbackedPagesSeen.size() << " (4KB granularity)" << endl;
    *out << "  Unbacked-entry alerts:      " << gUnbackedAlertCount << endl;
    *out << "  API calls from unbacked:    " << gApiFromUnbackedCount
         << " (VirtualAlloc/VirtualAllocEx/CreateThread/CreateRemoteThread invoked by unbacked code)" << endl;
    if (gHasFirstAlert)
    {
        *out << "  First unbacked execution:  ts=" << gFirstAlertTs << " addr=0x" << std::hex << gFirstAlertAddr
             << std::dec << " tid=" << gFirstAlertTid << endl;
    }
    else
    {
        *out << "  First unbacked execution:  (none observed)" << endl;
    }

    if (KnobDumpModules)
    {
        *out << "-----------------------------------------------" << endl;
        *out << "Per-module breakdown (module-backed only; fileless/unbacked reported above):" << endl;
        for (auto& kv : gModuleStats)
        {
            if (kv.second->isUnbacked) continue; // already covered by the dedicated section above
            *out << "  " << (kv.second->isNoise ? "[noise]      " : "[interesting]") << " " << kv.first
                 << " ins=" << kv.second->insCount << " bbl=" << kv.second->bblCount << endl;
        }
    }
    *out << "===============================================" << endl;
}

void InitTracker()
{
    PIN_InitLock(&gMapLock);
    PIN_InitLock(&gAlertLock);

    string fileName = KnobOutputFile.Value();
    if (!fileName.empty())
    {
        out = new std::ofstream(fileName.c_str());
    }
}
