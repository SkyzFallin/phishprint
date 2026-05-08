"""JSON serialization. dataclasses.asdict handles the nested structure."""
from __future__ import annotations

import json

from phishprint.scan import Report


def to_json(report: Report, *, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, default=str, sort_keys=False)
