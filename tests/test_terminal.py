from __future__ import annotations

from io import StringIO

from netdiag.cli import _print_findings
from netdiag.findings import Finding, Severity
from netdiag.report import print_report
from netdiag.terminal import terminal_safe


def test_terminal_safe_visibly_escapes_ansi_osc_newline_and_bidi() -> None:
    hostile = "Family\x1b[2J\x1b]8;;https://evil.example\x07WiFi\nforged\u202eabc"
    rendered = terminal_safe(hostile)
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "\n" not in rendered
    assert "\u202e" not in rendered
    assert r"\x1b[2J" in rendered
    assert r"\x1b]8;;https://evil.example\x07" in rendered
    assert r"\nforged\u202eabc" in rendered


def test_terminal_safe_bounds_input_before_escape_expansion() -> None:
    rendered = terminal_safe("\x1b" * 100, max_chars=4)
    assert rendered == r"\x1b\x1b\x1b\x1b…"


def test_standalone_finding_sink_cannot_emit_controls(capsys) -> None:
    _print_findings(
        [
            Finding(
                Severity.WARN,
                "wifi",
                "Wi-Fi\x1b[2J title",
                "detail\n[CRIT] forged",
                "hint\u202e spoof",
            )
        ]
    )
    rendered = capsys.readouterr().out
    assert "\x1b" not in rendered
    assert "\u202e" not in rendered
    assert r"\x1b[2J" in rendered
    assert r"detail\n[CRIT] forged" in rendered
    assert rendered.count("[CRIT]") == 1


def test_human_report_sink_cannot_emit_controls_or_forged_lines() -> None:
    class HostileReport:
        @staticmethod
        def to_dict(*, redact: bool = False):
            del redact
            return {
                "hostname": "Family\x1b]0;owned\x07Mac\u2066",
                "os": {"system": "Darwin"},
                "outcome": "degraded",
                "severity": "warn",
                "duration_ms": 3,
                "coverage": {"status": "complete", "completed": 1, "planned": 1},
                "assessment": "Review\nforged heading",
                "findings": [
                    {
                        "category": "wifi\x1b]8;;bad\x07\nspoof\u202e",
                        "severity": "warn",
                        "title": "Wi-Fi\x1b[2J title",
                        "detail": "detail\n[CRIT] forged",
                        "hint": "hint\u202e spoof",
                    }
                ],
            }

    output = StringIO()
    print_report(HostileReport(), file=output)  # type: ignore[arg-type]
    rendered = output.getvalue()
    assert "\x1b" not in rendered
    assert "\x07" not in rendered
    assert "\u2066" not in rendered
    assert "\u202e" not in rendered
    assert r"\x1b]0;owned\x07" in rendered
    assert r"detail\n[CRIT] forged" in rendered
    assert rendered.count("[CRIT]") == 1
