from __future__ import annotations

import json
from importlib.resources import files

from netdiag.ui.assets import verify_asset_manifest


def test_packaged_schema_is_available_and_valid_json() -> None:
    schema = files("netdiag.schemas").joinpath("report-1.1.schema.json")
    payload = json.loads(schema.read_text(encoding="utf-8"))
    assert payload["$id"].endswith("report-1.1.schema.json")
    assert payload["properties"]["schema_version"]["const"] == "1.1"


def test_packaged_ui_asset_manifest_is_complete() -> None:
    loaded = verify_asset_manifest()
    assert {asset.spec.filename for asset in loaded} == {
        "index.html",
        "styles.css",
        "app.js",
        "icons.svg",
    }
