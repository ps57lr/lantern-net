"""Human-readable and JSON report output."""

from __future__ import annotations

import json
import sys

from netdiag.findings import Severity
from netdiag.scanner import Report

_ICONS = {
    Severity.OK: "✓",
    Severity.INFO: "·",
    Severity.WARN: "⚠",
    Severity.CRIT: "✗",
}


def print_report(
    report: Report, *, json_out: bool = False, redact: bool = False, file=None
) -> None:
    file = file or sys.stdout
    payload = report.to_dict(redact=redact)
    if json_out:
        json.dump(payload, file, indent=2)
        file.write("\n")
        return

    print(f"netdiag report — {payload['hostname']} ({payload['os']['system']})", file=file)
    print(f"Overall: {payload['severity'].upper()} · {payload['duration_ms']} ms", file=file)
    print("-" * 60, file=file)

    by_cat: dict[str, list] = {}
    for finding in payload["findings"]:
        by_cat.setdefault(finding["category"], []).append(finding)

    category_order = {name: index for index, name in enumerate(("route", "wifi", "dns", "lan", "mdns", "ports"))}
    for cat in sorted(by_cat.keys(), key=lambda name: (category_order.get(name, 99), name)):
        print(f"\n[{cat.upper()}]", file=file)
        for f in by_cat[cat]:
            icon = _ICONS.get(Severity(f["severity"]), "·")
            print(f"  {icon} {f['title']}", file=file)
            if f["detail"]:
                for line in f["detail"].splitlines()[:4]:
                    print(f"      {line}", file=file)
            if f["hint"]:
                print(f"      → {f['hint']}", file=file)

    actions = [
        finding["hint"]
        for finding in payload["findings"]
        if finding["severity"] in {"crit", "warn"} and finding["hint"]
    ]
    if actions:
        print("\n[NEXT STEPS]", file=file)
        for number, action in enumerate(dict.fromkeys(actions), start=1):
            print(f"  {number}. {action}", file=file)

    print(file=file)
