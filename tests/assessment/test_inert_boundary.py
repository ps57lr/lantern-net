from __future__ import annotations

import ast
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ASSESSMENT_ROOT = REPOSITORY_ROOT / "netdiag" / "assessment"


def test_assessment_package_does_not_import_execution_or_io_capabilities() -> None:
    forbidden_roots = {
        "asyncio",
        "http",
        "os",
        "pathlib",
        "requests",
        "shlex",
        "socket",
        "subprocess",
        "urllib",
    }
    for source_path in ASSESSMENT_ROOT.glob("*.py"):
        tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imports.add(node.module.split(".", 1)[0])
        assert not imports & forbidden_roots, (
            f"{source_path.name} imports {imports & forbidden_roots}"
        )


def test_assessment_foundation_is_not_wired_into_cli_ui_or_runtime_paths() -> None:
    runtime_paths = [
        REPOSITORY_ROOT / "netdiag" / "__init__.py",
        REPOSITORY_ROOT / "netdiag" / "__main__.py",
        REPOSITORY_ROOT / "netdiag" / "application.py",
        REPOSITORY_ROOT / "netdiag" / "cli.py",
        REPOSITORY_ROOT / "netdiag" / "scanner.py",
    ]
    runtime_paths.extend((REPOSITORY_ROOT / "netdiag" / "ui").glob("*.py"))
    runtime_paths.extend((REPOSITORY_ROOT / "netdiag" / "lan").glob("*.py"))
    for source_path in runtime_paths:
        source = source_path.read_text(encoding="utf-8")
        assert "netdiag.assessment" not in source
        assert "from .assessment" not in source


def test_assessment_source_has_no_execution_hook_vocabulary() -> None:
    forbidden_fragments = (
        "shell=True",
        "os.system",
        "subprocess.",
        "socket.",
        "http://",
        "https://",
        "plugin_hook",
        "credential_value",
    )
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(ASSESSMENT_ROOT.glob("*.py"))
    )
    for fragment in forbidden_fragments:
        assert fragment not in source
