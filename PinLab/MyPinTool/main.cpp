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
 *
 *  This file is intentionally thin: it owns only the Pin entry point and
 *  callback registration. Knobs/settings live in config.h/.cpp, shared data
 *  structures in types.h, helper functions in utils.h/.cpp, and all actual
 *  instrumentation/analysis logic in tracker.h/.cpp.
 */

#include "pin.H"
#include "config.h"
#include "tracker.h"

#include <iostream>

using std::cerr;
using std::endl;

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

/*!
 * The main procedure of the tool.
 */
int main(int argc, char* argv[])
{
    // Required before any RTN_FindByName / RTN_FindByAddress / export-table symbol lookup
    // will succeed -- without this, Pin never parses export tables and every such lookup
    // silently fails.
    PIN_InitSymbols();

    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    // Knob values are only available after PIN_Init() parses the command line.
    InitConfig();
    InitTracker();

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

    // Start the program, never returns.
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
