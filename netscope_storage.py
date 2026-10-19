"""Small JSON storage helpers for NetScope feature history."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
INFORMATION_DIR = ROOT / "Information"

CATEGORIES = (
    "nmap",
    "dns",
    "dns_addresses",
    "reverse_dns",
    "http",
    "http_headers",
    "http_status",
    "whois",
    "tcp",
    "common_ports",
    "ping",
    "traceroute",
    "tls",
    "subnet",
    "local_network",
    "dependency",
)


def ensure_information_dir() -> None:
    INFORMATION_DIR.mkdir(exist_ok=True)
    for category in CATEGORIES:
        path = INFORMATION_DIR / f"{category}.json"
        if not path.exists():
            path.write_text("[]\n", encoding="utf-8")


def information_path(category: str) -> Path:
    if category not in CATEGORIES:
        raise ValueError(f"Unknown information category: {category}")
    ensure_information_dir()
    return INFORMATION_DIR / f"{category}.json"


def load_records(category: str) -> list[dict[str, Any]]:
    path = information_path(category)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []


def save_record(category: str, record: dict[str, Any]) -> None:
    records = load_records(category)
    enriched = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        **record,
    }
    records.append(enriched)
    information_path(category).write_text(
        json.dumps(records, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def save_records(category: str, records: list[dict[str, Any]]) -> None:
    information_path(category).write_text(
        json.dumps(records, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
