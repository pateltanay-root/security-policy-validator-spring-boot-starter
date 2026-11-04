#!/usr/bin/env python3
"""Evaluate validator reports against endpoint-level ground truth.

Supported formats: JSON, CSV, DOCX, and labelled text reports.
The DOCX parser handles reports that list Severity before Endpoint and Type.
"""
import argparse
import csv
import json
import math
import os
import re
import zipfile
import xml.etree.ElementTree as ET
from collections import defaultdict

TYPES = (
    "MISSING_POLICY", "AUTHENTICATION_MISSING", "AUTHORIZATION_MISSING",
    "ACCESS_TYPE_MISMATCH", "ROLE_MISMATCH", "INVALID_PUBLIC_POLICY",
    "INVALID_AUTHENTICATED_POLICY", "UNKNOWN_ACCESS_TYPE",
)
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
ENDPOINT_RE = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH)\b\s*[:|]?\s*(/[^\s|,;\)\]]*)", re.I)
WORD_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def load_truth(path):
    with open(path, newline="", encoding="utf-8-sig") as stream:
        rows = list(csv.DictReader(stream))
    required = {"endpoint", "label", "expected_violation", "expected_severity"}
    if not rows or not required.issubset(rows[0]):
        raise ValueError(f"Ground truth must contain columns: {sorted(required)}")
    truth = {r["endpoint"].strip(): r for r in rows}
    if len(truth) != len(rows):
        raise ValueError("Duplicate endpoint keys in ground-truth CSV")
    return truth


def finding(endpoint, violation_type, severity):
    return {
        "endpoint": endpoint.strip().rstrip(".,"),
        "violationType": violation_type.strip().upper(),
        "severity": (severity or "").strip().upper(),
    }


def parse_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        columns = {x.strip().lower(): x for x in (reader.fieldnames or [])}
        ep = columns.get("endpoint")
        typ = columns.get("type") or columns.get("violationtype") or columns.get("violation_type")
        sev = columns.get("severity")
        if not (ep and typ and sev):
            raise ValueError("CSV report must include Endpoint, Type, and Severity columns")
        return [finding(r[ep], r[typ], r[sev]) for r in reader if r.get(ep) and r.get(typ)]


def docx_units(path):
    with zipfile.ZipFile(path) as archive:
        root = ET.fromstring(archive.read("word/document.xml"))
    body = root.find(WORD_NS + "body")
    if body is None:
        raise ValueError("DOCX has no document body")
    text = lambda node: "".join(t.text or "" for t in node.iter(WORD_NS + "t"))
    for element in body:
        if element.tag == WORD_NS + "p":
            yield text(element)
        elif element.tag == WORD_NS + "tbl":
            for row in element.iter(WORD_NS + "tr"):
                yield " | ".join(text(cell) for cell in row.findall(WORD_NS + "tc"))


def parse_labelled_units(units):
    """Start a new finding at each Severity label; works for Severity/Endpoint/Type order."""
    parsed = []
    current = {"endpoint": "", "type": "", "severity": ""}

    def flush():
        nonlocal current
        if current["endpoint"] and current["type"]:
            parsed.append(finding(current["endpoint"], current["type"], current["severity"]))
        current = {"endpoint": "", "type": "", "severity": ""}

    for raw in units:
        line = re.sub(r"\s+", " ", str(raw)).strip()
        if not line:
            continue
        if re.fullmatch(r"[-=_\s]{5,}", line):
            flush()
            continue

        sev = re.search(r"\bSeverity\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW)\b", line, re.I)
        ep = ENDPOINT_RE.search(line)
        typ = re.search(r"\b(" + "|".join(map(re.escape, TYPES)) + r")\b", line, re.I)

        # In the supplied DOCX, Severity starts each record. Flush the prior
        # completed finding before assigning this severity to the next one.
        if sev and (current["endpoint"] or current["type"]):
            flush()
        if ep and current["endpoint"] and current["type"]:
            flush()
        if ep and not current["endpoint"]:
            current["endpoint"] = f"{ep.group(1).upper()}:{ep.group(2).rstrip('.,')}"
        if typ and not current["type"]:
            current["type"] = typ.group(1).upper()
        if sev and not current["severity"]:
            current["severity"] = sev.group(1).upper()

    flush()
    return parsed


def parse_json(path):
    data = json.load(open(path, encoding="utf-8-sig"))
    rows = data.get("violations", []) if isinstance(data, dict) else data
    result = []
    for r in rows:
        ep = r.get("endpoint") or r.get("Endpoint")
        typ = r.get("violationType") or r.get("type") or r.get("Type")
        sev = r.get("severity") or r.get("Severity") or ""
        if ep and typ:
            result.append(finding(ep, typ, sev))
    return result


def parse_report(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".csv":
        return parse_csv(path)
    if ext == ".json":
        return parse_json(path)
    if ext == ".docx":
        return parse_labelled_units(docx_units(path))
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16", errors="replace")
    elif len(raw) > 1 and raw[1:2] == b"\x00":
        text = raw.decode("utf-16-le", errors="replace")
    else:
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            text = raw.decode("cp1252", errors="replace")
    return parse_labelled_units(text.splitlines())


def evaluate(truth, findings):
    by_endpoint = defaultdict(list)
    for f in findings:
        by_endpoint[f["endpoint"]].append((f["violationType"], f["severity"]))
    tp = fp = fn = tn = type_ok = severity_ok = 0
    for endpoint, row in truth.items():
        positive = row["label"].strip().upper() == "MISCONFIGURED"
        actual = by_endpoint.get(endpoint, [])
        if positive and actual:
            tp += 1
            if row["expected_violation"].strip().upper() in {x[0] for x in actual}:
                type_ok += 1
            if row["expected_severity"].strip().upper() in {x[1] for x in actual}:
                severity_ok += 1
        elif positive:
            fn += 1
        elif actual:
            fp += 1
        else:
            tn += 1
    fp += sum(1 for endpoint in by_endpoint if endpoint not in truth)
    div = lambda n, d: n / d if d else 0.0
    p, r = div(tp, tp + fp), div(tp, tp + fn)
    specificity = div(tn, tn + fp)
    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": p, "recall": r, "f1": div(2*p*r, p+r),
        "accuracy": div(tp+tn, tp+fp+fn+tn),
        "specificity": specificity, "false_positive_rate": div(fp, tn+fp),
        "violation_type_accuracy": div(type_ok, tp),
        "severity_accuracy": div(severity_ok, tp),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--truth", default="ground_truth.csv")
    ap.add_argument("--report", required=True)
    ap.add_argument("--json", help="Optional metrics output path")
    args = ap.parse_args()
    truth = load_truth(args.truth)
    findings = parse_report(args.report)
    if not findings:
        raise SystemExit("No violations parsed; check the report format.")
    metrics = evaluate(truth, findings)
    print(f"Parsed {len(findings)} findings from {os.path.basename(args.report)}")
    print(f"Endpoints: {len(truth)} | TP={metrics['TP']} FP={metrics['FP']} FN={metrics['FN']} TN={metrics['TN']}")
    for key, value in metrics.items():
        if key not in {"TP", "FP", "FN", "TN"}:
            print(f"{key:26s} {value:.4f}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as stream:
            json.dump({"metrics": metrics}, stream, indent=2)


if __name__ == "__main__":
    main()
