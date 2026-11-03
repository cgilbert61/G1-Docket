"""
Governance Configuration Loader and Manager.
Loads settings from config.yaml, environment variables, or programmatic defaults.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List

import yaml

from governance.siem_forwarder import SIEMDestinationConfig


def load_governance_config(config_path: str | Path | None = None) -> Dict[str, Any]:
    default_path = Path(__file__).parent / "config.yaml"
    target_path = Path(config_path) if config_path else default_path

    if target_path.exists():
        with open(target_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
    else:
        cfg = {}

    server_cfg = cfg.get("server", {})
    storage_cfg = cfg.get("storage", {})

    return {
        "server": {
            "host": os.environ.get("GOVERNANCE_HOST", server_cfg.get("host", "0.0.0.0")),
            "port": int(os.environ.get("GOVERNANCE_PORT", server_cfg.get("port", 18084))),
            "inference_gateway_url": os.environ.get(
                "INFERENCE_GATEWAY_URL",
                server_cfg.get("inference_gateway_url", "http://localhost:18082"),
            ),
            "emergency_ticket_ttl_seconds": int(
                server_cfg.get("emergency_ticket_ttl_seconds", 7200)
            ),
        },
        "storage": {
            "worm_sqlite_path": os.environ.get(
                "WORM_SQLITE_PATH",
                storage_cfg.get("worm_sqlite_path", "data/governance/worm_ledger.db"),
            ),
            "worm_jsonl_path": os.environ.get(
                "WORM_JSONL_PATH",
                storage_cfg.get("worm_jsonl_path", "data/governance/worm_ledger.jsonl"),
            ),
            "quarantine_db_path": os.environ.get(
                "QUARANTINE_DB_PATH",
                storage_cfg.get("quarantine_db_path", "data/governance/quarantine.db"),
            ),
            "siem_buffer_db_path": os.environ.get(
                "SIEM_BUFFER_DB_PATH",
                storage_cfg.get("siem_buffer_db_path", "data/governance/siem_buffer.db"),
            ),
            "keys_dir": os.environ.get(
                "POD_KEY_DIR",
                storage_cfg.get("keys_dir", ".pod_keys"),
            ),
        },
        "siem_destinations": [
            SIEMDestinationConfig(**d) for d in cfg.get("siem_destinations", [])
        ],
    }
