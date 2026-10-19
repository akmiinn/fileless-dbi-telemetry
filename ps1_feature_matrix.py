import argparse
import os
import re
from pathlib import Path
from types import SimpleNamespace

import pandas as pd


def read_text(path):
    raw = Path(path).read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace"), "utf-8-sig"
    if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return raw.decode("utf-32", errors="replace"), "utf-32"
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace"), "utf-16"
    head = raw[:4096]
    if head and head.count(b"\x00") / len(head) > 0.3:
        enc = "utf-16-le" if head[1:2] == b"\x00" else "utf-16-be"
        return raw.decode(enc, errors="replace"), enc
    for enc in ("utf-8", "cp1252"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            pass
    return raw.decode("latin-1", errors="replace"), "latin-1"


_CONCAT_SAME = re.compile(r"""(['"])\s*\+\s*\1""")
_CONCAT_MIX = re.compile(r"""['"]\s*\+\s*['"]""")


def normalize(text):
    text = text.replace("`", "")
    text = _CONCAT_SAME.sub("", text)
    return _CONCAT_MIX.sub("", text)


_LIT_ASSIGN = re.compile(r"\$(\w+)\s*=\s*(['\"])((?:(?!\2)[^\r\n]){1,60})\2(?!\s*\+)")
_CONCAT_TOKEN = r"(?:\$\w+|'[^'\r\n]{0,60}'|\"[^\"\r\n]{0,60}\")"
_CONCAT_ASSIGN = re.compile(r"\$(\w+)\s*=\s*(" + _CONCAT_TOKEN + r"(?:\s*\+\s*" + _CONCAT_TOKEN + r"){1,9})(?!\s*\+)")
_TOKEN = re.compile(r"\$(\w+)|'([^'\r\n]{0,60})'|\"([^\"\r\n]{0,60})\"")
_APILIKE = re.compile(r"^[A-Za-z][A-Za-z0-9]{3,39}$")
_DLLLIKE = re.compile(r"^[\w]{2,20}\.dll$", re.IGNORECASE)


def resolve_split_strings(text, max_passes=6):
    resolved = {m.group(1): m.group(3) for m in _LIT_ASSIGN.finditer(text)}
    chains = [(m.group(1), m.group(2)) for m in _CONCAT_ASSIGN.finditer(text)]
    built = set()
    for _ in range(max_passes):
        progress = False
        for name, rhs in chains:
            if name in resolved:
                continue
            parts, ok = [], True
            for tm in _TOKEN.finditer(rhs):
                if tm.group(1) is not None:
                    v = resolved.get(tm.group(1))
                    if v is None:
                        ok = False
                        break
                    parts.append(v)
                else:
                    parts.append(tm.group(2) if tm.group(2) is not None else tm.group(3))
            if ok:
                val = "".join(parts)
                resolved[name] = val
                built.add(val)
                progress = True
        if not progress:
            break
    api_like = [v for v in built if _APILIKE.match(v) or _DLLLIKE.match(v)]
    new_hits = [v for v in api_like if v.lower() not in text.lower()]
    blob = "\n".join(f"## resolved: {v}" for v in api_like)
    return blob, len(new_hits)


def infer_family(stem):
    first = re.split(r"\s*[,:]\s*|\s+-\s+", stem.strip())[0]
    first = re.sub(r"[_\s]*\d+$", "", first).strip()
    m = re.match(r"^(\S+)\s+(dropper|stage\s*\d*|loader|payload)$", first, re.I)
    return (m.group(1) if m else first) or "Unknown"


I = re.IGNORECASE


def rx(pattern):
    c = re.compile(pattern, I)
    return lambda ctx: len(c.findall(ctx.norm))


_ASM_LOAD = re.compile(
    r"(?:\[\s*(?:System\.)?Reflection\.Assembly\s*\]\s*::|(?<![\w])Assembly\s*\.|CurrentDomain\s*\.)"
    r"\s*Load\s*\(\s*([^)\r\n]{0,120})", I)
_INVOKE_LOAD = re.compile(r"InvokeMember\s*\(\s*[\"']Load[\"']", I)
_ASM_NAMED = re.compile(
    r"-AssemblyName\b"
    r"|Assembly\s*\]\s*::\s*Load(?:From|File|WithPartialName)\b"
    r"|Add-Type\b[^\r\n]{0,120}?\s-(?:Path|LiteralPath)\b", I)


def _asm_load_counts(norm):
    mem = named = 0
    for m in _ASM_LOAD.finditer(norm):
        arg = m.group(1).lstrip()
        if arg[:1] in ("'", '"'):
            named += 1
        else:
            mem += 1
    mem += len(_INVOKE_LOAD.findall(norm))
    named += len(_ASM_NAMED.findall(norm))
    return mem, named


FEATURES = []


def add(name, cat, fn, hook, rule="count > 0"):
    FEATURES.append((name, cat, fn, hook, rule))


add("CreateProcessA/W", "API", rx(r"CreateProcess[AW]?(?![A-Za-z])"), "kernel32/KERNELBASE!CreateProcessA/W")
add("NtCreateUserProcess", "API", rx(r"(?:Nt|Zw)CreateUserProcess"), "ntdll!NtCreateUserProcess")
add("CREATE_SUSPENDED / 0x4", "API",
    lambda c: len(re.findall(r"CREATE_SUSPENDED", c.norm, I))
    + (len(re.findall(r"(?<![\w.])0x0*4(?![0-9A-Fa-f])", c.norm, I))
       if re.search(r"CreateProcess|CreateUserProcess", c.norm, I) else 0),
    "arg check: dwCreationFlags & 0x4 on CreateProcess")
add("VirtualAllocEx", "API", rx(r"VirtualAllocEx"), "KERNELBASE!VirtualAllocEx -> ntdll!NtAllocateVirtualMemory (remote handle)")
add("NtAllocateVirtualMemory", "API", rx(r"(?:Nt|Zw)AllocateVirtualMemory"), "ntdll!NtAllocateVirtualMemory")
add("PAGE_EXECUTE_READWRITE / 0x40", "API",
    lambda c: len(re.findall(r"PAGE_EXECUTE_READWRITE", c.norm, I))
    + len(re.findall(r"0x0*3000\s*,\s*0x0*40(?![0-9A-Fa-f])", c.norm, I))
    + (len(re.findall(r"(?<![\w.])0x0*40(?![0-9A-Fa-f])", c.norm, I))
       if re.search(r"VirtualAlloc|VirtualProtect|AllocateVirtualMemory|ProtectVirtualMemory", c.norm, I) else 0),
    "arg check: Protect == 0x40 on Alloc/ProtectVirtualMemory")
add("WriteProcessMemory", "API", rx(r"WriteProcessMemory"), "KERNELBASE!WriteProcessMemory -> ntdll!NtWriteVirtualMemory")
add("NtWriteVirtualMemory", "API", rx(r"(?:Nt|Zw)WriteVirtualMemory"), "ntdll!NtWriteVirtualMemory (scan buffer for MZ)")
add("NtUnmapViewOfSection", "API", rx(r"(?:Nt|Zw)UnmapViewOfSection"), "ntdll!NtUnmapViewOfSection (hollowing)")
add("QueueUserAPC", "API", rx(r"QueueUserAPC"), "KERNELBASE!QueueUserAPC -> ntdll!NtQueueApcThread")
add("NtQueueApcThread", "API", rx(r"(?:Nt|Zw)QueueApcThread(?:Ex)?"), "ntdll!NtQueueApcThread")
add("SetThreadContext", "API", rx(r"(?<![A-Za-z])(?:Wow64)?SetThreadContext"), "KERNELBASE!SetThreadContext -> ntdll!NtSetContextThread")
add("NtSetContextThread", "API", rx(r"(?:Nt|Zw)SetContextThread"), "ntdll!NtSetContextThread")
add("ResumeThread", "API", rx(r"(?<![A-Za-z])ResumeThread"), "KERNELBASE!ResumeThread -> ntdll!NtResumeThread")
add("NtResumeThread", "API", rx(r"(?:Nt|Zw)ResumeThread"), "ntdll!NtResumeThread")
add("SystemParametersInfo (benign baseline)", "API", rx(r"SystemParametersInfo[AW]?"), "none (benign noise reference)")
add("keybd_event (benign baseline)", "API", rx(r"keybd_event"), "none (benign noise reference)")
add("SendInput (benign baseline)", "API", rx(r"(?<![A-Za-z])SendInput(?![A-Za-z])"), "none (benign noise reference)")

add("Assembly.Load(byte[]) in-memory", "Reflection", lambda c: c.asm[0], "CLR module load with no file backing (Sysmon 7 / image-load with empty path)")
add("Assembly load by name/path (file-backed)", "Reflection", lambda c: c.asm[1], "none (benign noise reference)")
add(".Invoke()", "Reflection", rx(r"\.\s*Invoke\s*\(|InvokeMember\s*\("), "managed only; correlate with CLR load")
add("GetMethod()", "Reflection", rx(r"GetMethod\s*\("), "managed only; correlate with CLR load")
add("CreateInstance()", "Reflection", rx(r"CreateInstance\s*\("), "managed only; correlate with CLR load")
add("DefineDynamicAssembly", "Reflection", rx(r"DefineDynamicAssembly"), "CLR dynamic module creation (Reflection.Emit)")
add("GetDelegateForFunctionPointer", "Reflection", rx(r"GetDelegateForFunctionPointer"), "native call target of the generated delegate (hook the callee)")

add("AmsiScanBuffer", "Evasion", rx(r"AmsiScanBuffer"), "amsi!AmsiScanBuffer (detect patch / forced return)")
add("EtwEventWrite", "Evasion", rx(r"EtwEventWrite"), "ntdll!EtwEventWrite (detect patch)")
add("AddVectoredExceptionHandler", "Evasion", rx(r"AddVectoredExceptionHandler"), "ntdll!RtlAddVectoredExceptionHandler")
add("Debug registers Dr0-Dr3,Dr7", "Evasion", rx(r"(?<![A-Za-z0-9_+/=])Dr[0-37](?![A-Za-z0-9_+/=])"),
    "CONTEXT.Dr0-7 in NtSetContextThread / NtContinue (HWBP bypass)")
add("-ExecutionPolicy Bypass (-ep)", "Evasion", rx(r"-(?:ep|exec\w*|executionpolicy)\s+bypass"), "Sysmon 1 command line")
add("-WindowStyle Hidden (-w)", "Evasion",
    rx(r"-w(?:in(?:dowstyle)?)?\s+hidden|WindowStyle\s*=\s*(?:\[[^\]]*\]::)?[\"']?Hidden"), "Sysmon 1 command line")
add("-NonInteractive", "Evasion", rx(r"-n(?:on)?i(?:nteractive)?(?![A-Za-z])"), "Sysmon 1 command line")
add("Invoke-Expression / iex", "Evasion", rx(r"Invoke-Expression|(?<![\w$.\-])iex(?![\w\-])"), "managed only; PowerShell script-block log")
add("[ScriptBlock]::Create", "Evasion",
    rx(r"\[\s*(?:System\.Management\.Automation\.)?scriptblock\s*\]\s*::\s*Create"), "managed only; PowerShell script-block log")
add("Split-string var reassembly (DefinePInvokeMethod-style)", "Evasion",
    lambda c: c.split_new,
    "static only: $a+$b+$c... fragment chains are resolved before matching; flags any API/DLL-shaped result "
    "that never appears as a literal substring in the file (used with DefinePInvokeMethod/DefineDynamicAssembly "
    "to build P/Invoke bindings with no literal API or DLL name anywhere)")


def collect(root, category, normalise):
    rows = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files):
            if not fn.lower().endswith(".ps1") or fn.startswith("._"):
                continue
            path = Path(dirpath) / fn
            raw, enc = read_text(path)
            norm = normalize(raw) if normalise else raw
            blob, split_new = resolve_split_strings(norm)
            if blob:
                norm = norm + "\n" + blob
            ctx = SimpleNamespace(raw=raw, norm=norm, asm=_asm_load_counts(norm), split_new=split_new)
            rel = path.relative_to(root)
            row = {"Filename": fn, "Category": category, "Encoding": enc,
                   "Subcategory": infer_family(path.stem) if category == "Malware"
                   else (rel.parts[0] if len(rel.parts) > 1 else "(root)")}
            for name, _c, fn_, _h, _r in FEATURES:
                row[name] = fn_(ctx)
            rows.append(row)
    return rows


def tier(mprev, bprev):
    if mprev == 0 and bprev == 0:
        return "ABSENT"
    if bprev == 0:
        return "WATCH"
    return "NOISE" if bprev >= mprev else "CORRELATE"


def build_matrix(df):
    mal, ben = df[df.Category == "Malware"], df[df.Category == "Benign"]
    out = []
    for name, cat, _fn, hook, rule in FEATURES:
        mv, bv = mal[name], ben[name]
        mprev, bprev = 100 * (mv > 0).mean(), 100 * (bv > 0).mean()
        out.append({"Feature_Name": name, "Category": cat,
                    "Malware_Count": int(mv.sum()), "Malware_Prevalence (%)": round(mprev, 1),
                    "Benign_Count": int(bv.sum()), "Benign_Prevalence (%)": round(bprev, 1),
                    "Tier": tier(mprev, bprev), "Pin_Hook_Target": hook, "Rule": rule})
    m = pd.DataFrame(out)
    order = {"WATCH": 0, "CORRELATE": 1, "NOISE": 2, "ABSENT": 3}
    return m.assign(_o=m.Tier.map(order)).sort_values(["_o", "Malware_Prevalence (%)"], ascending=[True, False]).drop(columns="_o")


def md_table(df, cols):
    head = "| " + " | ".join(cols) + " |\n|" + "|".join("---" for _ in cols) + "|\n"
    return head + "".join("| " + " | ".join(str(r[c]) for c in cols) + " |\n" for _, r in df.iterrows())


def write_markdown(path, m, n_m, n_b, normalise):
    cols = ["Feature_Name", "Malware_Count", "Malware_Prevalence (%)", "Benign_Count", "Benign_Prevalence (%)", "Pin_Hook_Target"]
    text = ["# Pin-relevant static feature comparison: PowerShell malware vs benign\n",
            f"- Malware scripts: **{n_m}**  |  Benign scripts: **{n_b}**",
            f"- Matching on {'RAW' if not normalise else 'NORMALISED (backticks removed, adjacent quoted literals joined)'} text.",
            "- Prevalence = % of scripts with at least one hit. Tier rules: see script docstring.\n"]
    for t, title in [("WATCH", "WATCH: present in malware, never in benign (hook; any hit is suspicious)"),
                     ("CORRELATE", "CORRELATE: in both, higher in malware (hook; require a second signal)"),
                     ("NOISE", "NOISE: at least as common in benign (do not alert alone)"),
                     ("ABSENT", "ABSENT: in neither corpus (static text cannot see it; keep hooked if technique-critical)")]:
        sub = m[m.Tier == t]
        text += [f"\n## {title}\n", md_table(sub, cols) if len(sub) else "_none_\n"]
    text += ["\n## Limitations\n",
             "- Names built from `$a + $b + $c ...` variable-fragment chains (e.g. inside DefinePInvokeMethod) are "
             "resolved before matching, so a feature like WriteProcessMemory or VirtualAllocEx will now hit even "
             "when no literal API/DLL name string exists in the file. Names that are hash-resolved, "
             "Base64/XOR-encoded, or resolved by any other mechanism are still invisible to static regex; "
             "absence here does not mean the script never calls the API.",
             f"- Small malware corpus (n={n_m}) with near-duplicate samples: one file moves prevalence by {100/n_m:.1f} points.",
             "- Hex literals `0x4` and `0x40` are counted only in context (see rules)."]
    Path(path).write_text("\n".join(text) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="PowerShell Pin-relevant feature matrix (malware vs benign).")
    ap.add_argument("--malware", default="Malware Corpus")
    ap.add_argument("--benign", default="Benign Corpus")
    ap.add_argument("--out", default=".")
    ap.add_argument("--raw", action="store_true", help="skip text normalisation")
    a = ap.parse_args()
    for d in (a.malware, a.benign):
        if not os.path.isdir(d):
            raise SystemExit(f"[!] Directory not found: {d}")
    df = pd.DataFrame(collect(a.malware, "Malware", not a.raw) + collect(a.benign, "Benign", not a.raw))
    n_m, n_b = int((df.Category == "Malware").sum()), int((df.Category == "Benign").sum())
    if not n_m or not n_b:
        raise SystemExit("[!] One of the corpora has no .ps1 files.")
    m = build_matrix(df)
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    m.to_csv(out / "comparative_feature_matrix.csv", index=False, encoding="utf-8-sig")
    df.to_csv(out / "per_file_features.csv", index=False, encoding="utf-8-sig")
    write_markdown(out / "summary_matrix.md", m, n_m, n_b, not a.raw)

    pd.set_option("display.width", 220); pd.set_option("display.max_colwidth", 60)
    show = ["Feature_Name", "Malware_Count", "Malware_Prevalence (%)", "Benign_Count", "Benign_Prevalence (%)", "Tier"]
    print("=" * 110); print(f"PIN-RELEVANT FEATURE MATRIX  malware n={n_m}  benign n={n_b}"); print("=" * 110)
    for cat in ["API", "Reflection", "Evasion"]:
        print(f"\n--- {cat} ---"); print(m[m.Category == cat][show].to_string(index=False))
    print(f"\nWrote: {out/'comparative_feature_matrix.csv'}\n       {out/'per_file_features.csv'}\n       {out/'summary_matrix.md'}")


if __name__ == "__main__":
    main()
