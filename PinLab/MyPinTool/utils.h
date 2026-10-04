/*
 * Copyright (C) 2007-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#ifndef MYPINTOOL_UTILS_H
#define MYPINTOOL_UTILS_H

#include "pin.H"
#include <string>
#include <vector>

std::string ToLower(const std::string& s);
std::string BaseName(const std::string& path);
std::vector< std::string > SplitCsv(const std::string& csv);
std::string NowTimestamp();
bool MatchesAnyToken(const std::string& lowerName, const std::vector< std::string >& tokens);
bool MatchesToken(const std::string& lowerName, const std::string& token);
double bbl_pct(UINT64 part, UINT64 total);

// Safely hex-dumps up to n bytes at addr (via PIN_SafeCopy, so an unmapped/racing page can't
// crash the tool). Used to distinguish real shellcode from ordinary CLR JIT-stub bytes.
std::string HexDump(ADDRINT addr, UINT32 n);

#endif // MYPINTOOL_UTILS_H
