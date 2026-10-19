#!/usr/bin/env python3

import argparse
import base64
import importlib.util
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fm", HERE / "ps1_feature_matrix.py")
fm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fm)

PASCAL = re.compile(r"^[A-Z][A-Za-z0-9]{3,39}$")
Q = r"""['"]"""
RX_DEFINE = re.compile(r"DefinePInvokeMethod\s*\(\s*(" + Q + r")([^'\"\r\n]{1,60})\1", re.I)
RX_EXTERN = re.compile(r"\bextern\s+[\w\[\]<>.,\s*]{1,60}?\s+([A-Za-z_]\w{2,39})\s*\(", re.I)
RX_GPA = re.compile(r"GetProcAddress\s*\(\s*[^,\r\n]{1,80},\s*(" + Q + r")([^'\"\r\n]{1,60})\1", re.I)
RX_B64 = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")


def known_names():
    """Words already covered by a feature in ps1_feature_matrix.FEATURES (case-insensitive)."""
    out = set()
    for name, *_ in fm.FEATURES:
        out.update(w.lower() for w in re.split(r"[^A-Za-z0-9]+", name) if len(w) >= 4)
    for pre in ("nt", "zw"):
        out.update(pre + w for w in ("unmapviewofsection", "writevirtualmemory", "allocatevirtualmemory",
                                     "queueapcthread", "setcontextthread", "resumethread"))
    return out


def names_in(text):
    found = []
    for m in RX_DEFINE.finditer(text):
        found.append(m.group(2))
    for m in RX_GPA.finditer(text):
        found.append(m.group(2))
    for m in RX_EXTERN.finditer(text):
        found.append(m.group(1))
    return found


def decoded_blobs(text, limit=40):
    n = 0
    for m in RX_B64.finditer(text):
        if n >= limit:
            break
        s = m.group(0)
        try:
            d = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
        except Exception:
            continue
        if len(d) < 80:
            continue
        sample = d[:4000]
        if sum(32 <= b < 127 or b in (9, 10, 13) for b in sample) / len(sample) < 0.9:
            continue
        n += 1
        yield d.decode("utf-8", "replace")


def scan(path):
    raw, _ = fm.read_text(path)
    norm = fm.normalize(raw)
    cand = names_in(norm)
    blob, _n = fm.resolve_split_strings(norm)
    cand += [ln.split("## resolved: ", 1)[1] for ln in blob.splitlines() if ln.startswith("## resolved: ")]
    for dec in decoded_blobs(raw):
        cand += names_in(fm.normalize(dec))
    return [c for c in cand if PASCAL.match(c)]


def walk(root):
    for dp, _d, fs in os.walk(root):
        for fn in sorted(fs):
            if fn.lower().endswith(".ps1") and not fn.startswith("._"):
                yield Path(dp) / fn


def tally(root):
    files, counts = defaultdict(set), defaultdict(int)
    n = 0
    for p in walk(root):
        n += 1
        for c in scan(p):
            files[c].add(p.name)
            counts[c] += 1
    return files, counts, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malware", default="Malware Corpus")
    ap.add_argument("--benign", default="Benign Corpus")
    ap.add_argument("--out", default="candidate_apis.csv")
    a = ap.parse_args()
    mf, mc, nm = tally(a.malware)
    bf, bc, nb = tally(a.benign)
    known = known_names()
    rows = []
    for name in set(mf) | set(bf):
        mfn, bfn = len(mf.get(name, ())), len(bf.get(name, ()))
        rows.append({"API_Name": name, "Malware_Files": mfn, "Malware_Count": mc.get(name, 0),
                     "Malware_Prevalence (%)": round(100 * mfn / nm, 1),
                     "Benign_Files": bfn, "Benign_Count": bc.get(name, 0),
                     "Benign_Prevalence (%)": round(100 * bfn / nb, 1),
                     "Class": "malware-only" if bfn == 0 else ("benign-only" if mfn == 0 else "both"),
                     "Already_A_Feature": name.lower() in known})
    df = pd.DataFrame(rows)
    df["_o"] = df.Class.map({"malware-only": 0, "both": 1, "benign-only": 2})
    df = df.sort_values(["_o", "Malware_Files", "Malware_Count"], ascending=[True, False, False]).drop(columns="_o")
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(a.out, index=False, encoding="utf-8-sig")
    print(f"malware n={nm}  benign n={nb}  distinct names={len(df)}")
    print(df.Class.value_counts().to_string())
    print(df[(df.Class == "malware-only")].head(25).to_string(index=False))
    print(f"Wrote {a.out}")


if __name__ == "__main__":
    main()
