/*
 * Copyright (C) 2007-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  DBI ground-truth collector for script-hosted (PowerShell/.NET CLR) fileless
 *  execution analysis.
 *
 *  Baseline behavior (unfiltered) is preserved via -filter 0. With filtering
 *  enabled (default), the tool classifies every JITed trace by its backing
 *  image at instrumentation time and skips full per-basic-block analysis
 *  calls for known CLR/OS "noise" modules, while always fully instrumenting:
 *    (a) the target host image itself (e.g. powershell.exe), and
 *    (b) memory with NO backing image at all (IMG_FindByAddress invalid) --
 *        i.e. JIT-compiled / dynamically generated script code, which is
 *        exactly the fileless execution surface this research targets.
 *  Noise modules are not dropped silently: they are still counted, but at
 *  one aggregate call per trace instead of one call per basic block, which
 *  is where most of the per-instruction instrumentation overhead comes from
 *  in CLR-heavy workloads.
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <ctime>
#include <cstdio>
using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 threadCount = 0; // total number of threads, including main thread

std::ostream* out = &cerr;

// Per-module (or "[unbacked-jit]") dynamic execution stats.
// NOTE: counters are plain (non-atomic) UINT64s, matching Pin's own example
// tools' convention -- under multi-threaded targets this is a benign race
// (like-sized aligned increments), acceptable for approximate profiling
// counts. std::atomic is intentionally avoided here: <atomic> collides with
// pin.H's compatibility headers under MSVC and fails to compile.
struct ModuleStats
{
    UINT64 insCount = 0;
    UINT64 bblCount = 0;
    bool isNoise    = false;
    bool isUnbacked = false;
};

std::map<string, ModuleStats*> gModuleStats;
PIN_LOCK gMapLock; // guards structural changes (insertion) to gModuleStats only

// Unbacked-memory (fileless) execution alerting state.
static const ADDRINT kPageSize = 0x1000; // alert dedup granularity: one alert per newly-seen 4KB page
PIN_LOCK gAlertLock;
std::set<ADDRINT> gUnbackedPagesSeen;
UINT64 gUnbackedAlertCount = 0;
bool gHasFirstAlert        = false;
ADDRINT gFirstAlertAddr    = 0;
THREADID gFirstAlertTid    = 0;
string gFirstAlertTs;

// API-from-unbacked-caller alerting state (behavioral timeline of a payload: what it
// calls, not just where its code sits).
UINT64 gApiFromUnbackedCount = 0;

static const char* kWatchedApis[] = { "VirtualAlloc", "VirtualAllocEx", "CreateThread", "CreateRemoteThread" };
static const size_t kNumWatchedApis = sizeof(kWatchedApis) / sizeof(kWatchedApis[0]);
static std::vector< string > gWatchedApiTokens; // lowercased kWatchedApis, built in main()

/* ===================================================================== */
// Command line switches
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
    "deliberately NOT hooked -- see kWatchedApis comment for why.");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool collects DBI ground-truth execution data for script-hosted" << endl
         << "(e.g. PowerShell/.NET CLR) processes, filtering CLR/OS runtime noise" << endl
         << "from per-instruction instrumentation while preserving full fidelity" << endl
         << "for the target image and unbacked (JIT-compiled) memory." << endl
         << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

static string ToLower(const string& s)
{
    string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return r;
}

static string BaseName(const string& path)
{
    size_t pos = path.find_last_of("\\/");
    return (pos == string::npos) ? path : path.substr(pos + 1);
}

static std::vector< string > SplitCsv(const string& csv)
{
    std::vector< string > tokens;
    std::stringstream ss(csv);
    string item;
    while (std::getline(ss, item, ','))
    {
        if (!item.empty()) tokens.push_back(ToLower(item));
    }
    return tokens;
}

static string NowTimestamp()
{
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::tm* tmBuf = std::localtime(&t); // single-threaded call sites only (Fini/logging), static buffer is fine
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tmBuf);
    return string(buf);
}

static bool MatchesAnyToken(const string& lowerName, const std::vector< string >& tokens)
{
    for (size_t i = 0; i < tokens.size(); i++)
    {
        if (lowerName.find(tokens[i]) != string::npos) return true;
    }
    return false;
}

static bool MatchesToken(const string& lowerName, const string& token) { return lowerName.find(token) != string::npos; }

static std::vector< string > gNoiseTokens;
static string gTargetToken;

static double bbl_pct(UINT64 part, UINT64 total)
{
    return total == 0 ? 0.0 : (100.0 * (double)part / (double)total);
}

// Safely hex-dumps up to n bytes at addr (via PIN_SafeCopy, so an unmapped/racing page can't
// crash the tool). Used to distinguish real shellcode from ordinary CLR JIT-stub bytes.
static string HexDump(ADDRINT addr, UINT32 n)
{
    if (n == 0) return "";
    std::vector< UINT8 > buf(n);
    size_t copied = PIN_SafeCopy(&buf[0], (const VOID*)addr, n);

    std::stringstream ss;
    for (size_t i = 0; i < copied; i++)
    {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X ", buf[i]);
        ss << hex;
    }
    if (copied < n) ss << "(only " << copied << "/" << n << " bytes readable)";
    return ss.str();
}

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
VOID CountBbl(UINT32 numInstInBbl, ModuleStats* stats)
{
    stats->bblCount++;
    stats->insCount += numInstInBbl;
}

// Aggregate, per-trace accounting for noise modules: one call regardless of how many
// basic blocks the trace contains, to keep totals accurate without per-BBL overhead.
VOID CountTraceAggregate(UINT32 numInstInTrace, UINT32 numBblInTrace, ModuleStats* stats)
{
    stats->bblCount += numBblInTrace;
    stats->insCount += numInstInTrace;
}

// Real-time fileless-execution alert: fires when control enters memory with no backing PE
// image. This is the DBI ground-truth event that Sysmon/ETW have no equivalent for -- neither
// exposes "code began executing from this non-image-backed address" at instruction granularity.
VOID UnbackedAlert(ADDRINT insAddr, THREADID tid)
{
    string ts    = NowTimestamp();
    string bytes = HexDump(insAddr, KnobUnbackedDumpBytes.Value());

    PIN_GetLock(&gAlertLock, 1);
    gUnbackedAlertCount++;
    if (!gHasFirstAlert)
    {
        gHasFirstAlert   = true;
        gFirstAlertAddr  = insAddr;
        gFirstAlertTid   = tid;
        gFirstAlertTs    = ts;
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
VOID LogCallFromUnbacked(ADDRINT callerIp, ADDRINT targetAddr, ADDRINT rcx, ADDRINT rdx, THREADID tid)
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
        key             = IMG_Name(img);
        string base     = BaseName(key);
        string baseLow  = ToLower(base);
        bool isTarget   = MatchesToken(baseLow, gTargetToken);
        isNoise         = KnobFilter && !isTarget && MatchesAnyToken(baseLow, gNoiseTokens);
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

/*!
 * The main procedure of the tool.
 */
int main(int argc, char* argv[])
{
    // Required before any RTN_FindByName / export-table symbol lookup will succeed --
    // without this, Pin never parses export tables and every such lookup silently fails.
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    PIN_InitLock(&gMapLock);
    PIN_InitLock(&gAlertLock);

    string fileName = KnobOutputFile.Value();
    if (!fileName.empty())
    {
        out = new std::ofstream(fileName.c_str());
    }

    gNoiseTokens = SplitCsv(KnobNoiseModules.Value());
    gTargetToken = ToLower(KnobTargetImage.Value());
    for (size_t i = 0; i < kNumWatchedApis; i++) gWatchedApiTokens.push_back(ToLower(kWatchedApis[i]));

    if (KnobCount)
    {
        TRACE_AddInstrumentFunction(Trace, 0);
        PIN_AddThreadStartFunction(ThreadStart, 0);
        PIN_AddThreadFiniFunction(ThreadFini, 0);
        IMG_AddInstrumentFunction(ImageLoad, 0);
        IMG_AddUnloadFunction(ImageUnload, 0);
        PIN_AddFiniFunction(Fini, 0);
    }

    cerr << "===============================================" << endl;
    cerr << "This application is instrumented by MyPinTool" << endl;
    cerr << "Filtering: " << (KnobFilter ? "ENABLED" : "disabled") << " (target=" << KnobTargetImage.Value()
         << ")" << endl;
    if (!KnobOutputFile.Value().empty())
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr << "===============================================" << endl;

    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
