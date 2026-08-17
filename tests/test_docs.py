from __future__ import annotations

import json
import re
from pathlib import Path

from netdiag.models import Report
from netdiag.platform import OSInfo


def test_core_design_report_example_matches_current_serializer() -> None:
    document = (Path(__file__).parents[1] / "docs" / "architecture" / "CORE_DESIGN.md").read_text(
        encoding="utf-8"
    )
    match = re.search(
        r"<!-- report-1\.1-example:start -->\n```json\n(.*?)\n```\n"
        r"<!-- report-1\.1-example:end -->",
        document,
        re.DOTALL,
    )
    assert match is not None
    documented = json.loads(match.group(1))

    generated = Report(
        "example-device",
        OSInfo("Darwin", "25.0.0", "arm64"),
        "2026-08-17T12:00:00Z",
    ).to_dict(redact=True)
    generated["report_id"] = documented["report_id"]

    assert re.fullmatch(r"report-[0-9a-f]{32}", documented["report_id"])
    assert documented == generated
