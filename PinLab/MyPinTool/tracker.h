/*
 * Copyright (C) 2007-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef MYPINTOOL_TRACKER_H
#define MYPINTOOL_TRACKER_H

#include "pin.H"

// Must be called once, after InitConfig() and before TRACE_AddInstrumentFunction()/
// PIN_StartProgram() -- initializes the tracker's internal locks and opens the output
// file (if -o was given).
void InitTracker();

/* ===================================================================== */
// Pin instrumentation/analysis callbacks -- registered from main().
/* ===================================================================== */
VOID Trace(TRACE trace, VOID* v);
VOID ImageLoad(IMG img, VOID* v);
VOID ImageUnload(IMG img, VOID* v);
VOID ThreadStart(THREADID threadIndex, CONTEXT* ctxt, INT32 flags, VOID* v);
VOID ThreadFini(THREADID threadIndex, const CONTEXT* ctxt, INT32 code, VOID* v);
VOID Fini(INT32 code, VOID* v);

#endif // MYPINTOOL_TRACKER_H
