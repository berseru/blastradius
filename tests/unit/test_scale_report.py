"""The scale report is read by judges, so its arithmetic is tested here.

The CI job that produces the inputs cannot run in the unit suite, so the inputs
are written to a temporary directory in exactly the shape the CLI writes them.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[2] / "ci" / "scale_report.py"
_spec = importlib.util.spec_from_file_location("scale_report", MODULE_PATH)
scale_report = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(scale_report)


def _write_level(directory: Path, level: int, ms: float, versions: int) -> None:
    (directory / f"ingest-{level}.json").write_text(
        json.dumps(
            {
                "seeds": level,
                "packages": level * 2,
                "versions": versions,
                "rows_written": versions * 3,
                "fetch_seconds": 10.0,
                "parse_seconds": 1.5,
                "write_seconds": 4.5,
            }
        ),
        encoding="utf-8",
    )
    (directory / f"verify-{level}.json").write_text(
        json.dumps(
            {
                "graph_size": {"Pkg": level * 2, "Ver": versions, "DEPENDS": 7},
                "services": [
                    {"timings_ms": {name: ms for name in scale_report.QUERIES}},
                    {"timings_ms": {name: ms + 2 for name in scale_report.QUERIES}},
                ],
                "failures": [],
                "hydra": {"queries_run": 12, "total_query_ms": 34.5},
            }
        ),
        encoding="utf-8",
    )


def test_median_of_even_and_odd_samples() -> None:
    assert scale_report._median([3.0, 1.0, 2.0]) == 2.0
    assert scale_report._median([1.0, 2.0, 3.0, 4.0]) == 2.5
    assert scale_report._median([]) == 0.0


def test_level_totals_and_counts(tmp_path: Path) -> None:
    _write_level(tmp_path, 143, 10.0, 500)
    level = scale_report.read_level(tmp_path, 143)
    assert level["ingest_seconds"] == 16.0
    assert level["nodes"] == 143 * 2 + 500
    assert level["edges"] == 7
    assert level["services"] == 2
    assert level["median_ms"]["direct_hits"] == 11.0
    assert level["slowest_median_ms"] == 11.0


def test_markdown_table_has_one_row_per_level(tmp_path: Path) -> None:
    _write_level(tmp_path, 143, 10.0, 500)
    _write_level(tmp_path, 300, 14.0, 1100)
    levels = [scale_report.read_level(tmp_path, value) for value in (143, 300)]
    text = scale_report.to_markdown(levels)
    rows = [line for line in text.splitlines() if line.startswith("| 1") or line.startswith("| 3")]
    assert len(rows) == 2
    assert "2.2x in package versions" in text
    assert "0 query failures" in text
