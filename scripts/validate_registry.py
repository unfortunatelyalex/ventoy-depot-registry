from __future__ import annotations

import ipaddress
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
PROVIDER_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
FINGERPRINT = re.compile(r"^[A-Fa-f0-9]{40,64}$")
DRIVERS = {"github-releases", "gitlab-releases", "static-json", "directory-index", "checksum-list", "sidecar", "static-html", "latest-redirect"}
IDENTITY_FIELDS = {"product_id", "edition", "flavor", "channel", "architecture", "language", "version", "build"}


def load(path: Path) -> Any:
    if path.stat().st_size > 1024 * 1024:
        raise ValueError(f"{path}: exceeds 1 MiB")
    return json.loads(path.read_text(encoding="utf-8"))


def walk(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            yield from walk(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from walk(item, (*path, str(index)))


def validate_url(url: str, hosts: set[str], path: Path) -> None:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or parsed.username or parsed.password or host not in hosts:
        raise ValueError(f"{path}: unsafe or non-allow-listed URL {url!r}")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if host == "localhost" or host.endswith(".localhost") or host.endswith(".local"):
            raise ValueError(f"{path}: local URL host")
    else:
        if not address.is_global:
            raise ValueError(f"{path}: private or local URL host")
    if any(part == ".." for part in parsed.path.split("/")):
        raise ValueError(f"{path}: path traversal in URL")


def validate_regex(expression: str, path: Path) -> re.Pattern[str]:
    nested_wildcard = re.search(r"\((?:\?:)?(?:\.\*|\.\+|\\w[+*]|\\d[+*])\)[+*{]", expression)
    if not expression or len(expression) > 512 or nested_wildcard:
        raise ValueError(f"{path}: unsafe detection regex")
    return re.compile(expression, re.IGNORECASE)


def resolve_identity(template: dict[str, Any], match: re.Match[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    groups = match.groupdict()
    for key, value in template.items():
        if isinstance(value, str) and value.startswith("$group:"):
            result[key] = groups.get(value.removeprefix("$group:"))
        else:
            result[key] = value
    return result


def validate_identity(identity: Any, path: Path) -> None:
    if not isinstance(identity, dict) or set(identity) - IDENTITY_FIELDS:
        raise ValueError(f"{path}: invalid identity fields")
    if not {"product_id", "channel", "architecture"} <= set(identity):
        raise ValueError(f"{path}: incomplete identity")


def validate_provider(path: Path) -> tuple[str, dict[str, Any]]:
    value = load(path)
    required = {"schema_version", "provider_id", "display_name", "homepage_url", "driver", "allowed_hosts", "capabilities", "release_sources", "detection"}
    if value.get("schema_version") != 1 or required - value.keys():
        raise ValueError(f"{path}: missing required v1 fields")
    provider_id = value["provider_id"]
    if not PROVIDER_ID.fullmatch(provider_id) or value["driver"] not in DRIVERS:
        raise ValueError(f"{path}: invalid provider id or driver")
    hosts = value["allowed_hosts"]
    if not isinstance(hosts, list) or not hosts or len(hosts) != len(set(hosts)) or any(not isinstance(host, str) or "/" in host or ":" in host for host in hosts):
        raise ValueError(f"{path}: invalid host allow-list")
    host_set = {host.lower() for host in hosts}
    for item_path, item in walk(value):
        key = item_path[-1] if item_path else ""
        if (key.endswith("_url") or key.endswith("_template")) and isinstance(item, str):
            validate_url(item, host_set, path)
        if key in {"regex", "artifact_regex", "link_regex", "entry_regex"} and isinstance(item, str):
            validate_regex(item, path)
        if key == "signer_fingerprints" and (not item or any(not FINGERPRINT.fullmatch(fingerprint) for fingerprint in item)):
            raise ValueError(f"{path}: incomplete signer fingerprint")
    rules = value["detection"]
    if not isinstance(rules, list) or not rules:
        raise ValueError(f"{path}: detection rules required")
    for rule in rules:
        validate_identity(rule.get("identity"), path)
        validate_regex(rule.get("regex", ""), path)
    for source in value["release_sources"]:
        validate_identity(source.get("identity"), path)
        verification = source.get("verification", {})
        if verification.get("level") == "SIGNED" and "signature" not in verification:
            raise ValueError(f"{path}: SIGNED source lacks signature policy")
    return provider_id, value


def validate_fixtures(provider_id: str, provider: dict[str, Any], fixture: Any) -> set[str]:
    if not isinstance(fixture, dict) or not fixture.get("matches") or not fixture.get("non_matches"):
        raise ValueError(f"{provider_id}: fixtures require matches and non_matches")
    rules = [(validate_regex(rule["regex"], Path(provider_id)), rule) for rule in provider["detection"]]
    filenames: set[str] = set()
    for case in fixture["matches"]:
        filename = case["filename"]
        filenames.add(filename)
        matches = [(regex.fullmatch(filename), rule) for regex, rule in rules]
        matches = [(match, rule) for match, rule in matches if match is not None]
        if len(matches) != 1:
            raise ValueError(f"{provider_id}: {filename!r} matched {len(matches)} rules")
        actual = resolve_identity(matches[0][1]["identity"], matches[0][0])
        if actual != case["identity"]:
            raise ValueError(f"{provider_id}: identity mismatch for {filename!r}: {actual!r}")
    for filename in fixture["non_matches"]:
        if any(regex.fullmatch(filename) for regex, _ in rules):
            raise ValueError(f"{provider_id}: negative fixture matched {filename!r}")
    return filenames


def main() -> int:
    index = load(ROOT / "providers" / "index.json")
    fixtures = load(ROOT / "fixtures" / "detection.json").get("providers", {})
    providers = dict(validate_provider(path) for path in sorted((ROOT / "providers").glob("*.json")) if path.name != "index.json")
    declared = index.get("providers", [])
    if sorted(providers) != declared or set(providers) != set(fixtures):
        raise ValueError("provider index, provider files and fixtures do not match")
    seen: dict[str, str] = {}
    for provider_id, provider in providers.items():
        for filename in validate_fixtures(provider_id, provider, fixtures[provider_id]):
            if filename in seen:
                raise ValueError(f"fixture collision: {filename!r} belongs to {seen[filename]} and {provider_id}")
            seen[filename] = provider_id
    print(f"validated {len(providers)} provider(s), {len(seen)} positive fixture(s)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, re.error) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1) from error
