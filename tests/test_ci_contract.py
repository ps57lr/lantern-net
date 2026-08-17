"""Release-workflow contracts that keep source and wheel acceptance aligned."""

from __future__ import annotations

from pathlib import Path


def test_browser_ci_exercises_source_and_isolated_wheel() -> None:
    workflow = (Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert '"setuptools==80.9.0"' in workflow
    assert "--no-deps --no-build-isolation" in workflow
    assert "lantern-browser-wheel/bin/python" in workflow
    assert 'LANTERN_INSTALLED_PACKAGE: "1"' in workflow
    assert workflow.count("run: npm run test:browser") == 2
    assert "npm ci --ignore-scripts --no-audit --no-fund" in workflow
