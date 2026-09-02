from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
FINGERPRINT = re.compile(r"^[A-Fa-f0-9]{40,64}$")
DRIVERS = {"github-releases", "gitlab-releases", "static-json", "directory-index", "checksum-list", "sidecar", "static-html", "latest-redirect"}


def load(path: Path) -> Any:
    if path.stat().st_size > 1024 * 1024:
        raise ValueError(f"{path}: exceeds 1 MiB")
    return json.loads(path.read_text(encoding="utf-8"))


def validate_provider(path: Path) -> str:
    value = load(path)
    required = {"schema_version", "provider_id", "driver", "allowed_hosts", "detection"}
    if value.get("schema_version") != 1 or required - value.keys():
        raise ValueError(f"{path}: missing required v1 fields")
    provider_id = value["provider_id"]
    if not PROVIDER_ID.fullmatch(provider_id) or value["driver"] not in DRIVERS:
        raise ValueError(f"{path}: invalid provider id or driver")
    hosts = value["allowed_hosts"]
    if not hosts or any("/" in host or ":" in host for host in hosts):
        raise ValueError(f"{path}: invalid host allow-list")
    for key, item in value.items():
        if key.endswith("_url") and item is not None and not item.startswith("https://"):
            raise ValueError(f"{path}: non-HTTPS URL")
    if value.get("checksum_algorithm", "sha256") not in {"sha256", "sha512"}:
        raise ValueError(f"{path}: weak checksum")
    if any(not FINGERPRINT.fullmatch(item) for item in value.get("signer_fingerprints", [])):
        raise ValueError(f"{path}: incomplete signer fingerprint")
    for rule in value["detection"]:
        expression = rule.get("regex", "")
        if len(expression) > 512 or re.search(r"\([^)]*[+*][^)]*\)[+*{]", expression):
            raise ValueError(f"{path}: unsafe detection regex")
        re.compile(expression)
    return provider_id


def main() -> int:
    index = load(ROOT / "providers" / "index.json")
    fixtures = load(ROOT / "fixtures" / "detection.json").get("providers", {})
    actual = {validate_provider(path) for path in sorted((ROOT / "providers").glob("*.json")) if path.name != "index.json"}
    declared = set(index.get("providers", []))
    if actual != declared:
        raise ValueError("provider index does not match provider files")
    if any(provider not in fixtures for provider in actual):
        raise ValueError("every provider requires detection fixtures")
    print(f"validated {len(actual)} provider(s)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, re.error) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error

