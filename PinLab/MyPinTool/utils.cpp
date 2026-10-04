/*
 * Copyright (C) 2007-2023 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include "pin.H"
#include "utils.h"

#include <sstream>
#include <algorithm>
#include <ctime>
#include <cstdio>

using std::string;
using std::vector;
using std::stringstream;

string ToLower(const string& s)
{
    string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return r;
}

string BaseName(const string& path)
{
    size_t pos = path.find_last_of("\\/");
    return (pos == string::npos) ? path : path.substr(pos + 1);
}

vector< string > SplitCsv(const string& csv)
{
    vector< string > tokens;
    stringstream ss(csv);
    string item;
    while (std::getline(ss, item, ','))
    {
        if (!item.empty()) tokens.push_back(ToLower(item));
    }
    return tokens;
}

string NowTimestamp()
{
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::tm* tmBuf = std::localtime(&t); // single-threaded call sites only (Fini/logging), static buffer is fine
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tmBuf);
    return string(buf);
}

bool MatchesAnyToken(const string& lowerName, const vector< string >& tokens)
{
    for (size_t i = 0; i < tokens.size(); i++)
    {
        if (lowerName.find(tokens[i]) != string::npos) return true;
    }
    return false;
}

bool MatchesToken(const string& lowerName, const string& token) { return lowerName.find(token) != string::npos; }

double bbl_pct(UINT64 part, UINT64 total) { return total == 0 ? 0.0 : (100.0 * (double)part / (double)total); }

string HexDump(ADDRINT addr, UINT32 n)
{
    if (n == 0) return "";
    vector< UINT8 > buf(n);
    size_t copied = PIN_SafeCopy(&buf[0], (const VOID*)addr, n);

    stringstream ss;
    for (size_t i = 0; i < copied; i++)
    {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02X ", buf[i]);
        ss << hex;
    }
    if (copied < n) ss << "(only " << copied << "/" << n << " bytes readable)";
    return ss.str();
}
