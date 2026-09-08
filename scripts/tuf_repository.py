from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from securesystemslib.signer import CryptoSigner
from tuf.api.metadata import (
    Metadata,
    MetaFile,
    Root,
    Snapshot,
    TargetFile,
    Targets,
    Timestamp,
)

REPOSITORY = Path(__file__).resolve().parents[1]
ROLE_EXPIRY = {"root": 365, "targets": 90, "snapshot": 30, "timestamp": 14}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Initialize or refresh the signed Ventoy Depot TUF repository."
    )
    result.add_argument("command", choices=("init", "publish"))
    result.add_argument(
        "offline_key_directory",
        type=Path,
        help="External directory for the offline root and targets keys.",
    )
    result.add_argument(
        "--online-key-directory",
        type=Path,
        required=True,
        help="Separate external directory for snapshot and timestamp keys.",
    )
    result.add_argument(
        "--output-root",
        type=Path,
        default=REPOSITORY / "public",
        help="Generated GitHub Pages tree (default: public/).",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    offline_key_directory = arguments.offline_key_directory.expanduser().resolve()
    online_key_directory = arguments.online_key_directory.expanduser().resolve()
    output_root = arguments.output_root.expanduser().resolve()
    _require_external_key_directory(offline_key_directory)
    _require_external_key_directory(online_key_directory)
    _require_separate_key_directories(offline_key_directory, online_key_directory)
    if arguments.command == "init":
        initialize(offline_key_directory, online_key_directory, output_root)
    else:
        publish(offline_key_directory, online_key_directory, output_root)
    print(f"Generated signed TUF repository at {output_root}")
    return 0


def initialize(offline_keys: Path, online_keys: Path, output_root: Path) -> None:
    root_path = output_root / "metadata" / "root.json"
    key_paths = {
        "root": offline_keys / "root.pem",
        "targets": offline_keys / "targets.pem",
        "snapshot": online_keys / "snapshot.pem",
        "timestamp": online_keys / "timestamp.pem",
    }
    if root_path.exists() or any(path.exists() for path in key_paths.values()):
        raise RuntimeError("Refusing to overwrite an existing TUF root or private key.")
    for directory in (offline_keys, online_keys):
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
    signers = {role: _generate_signer(path) for role, path in key_paths.items()}
    root = Metadata(
        Root(
            version=1,
            expires=_expiry("root"),
            consistent_snapshot=False,
        )
    )
    for role, signer in signers.items():
        root.signed.add_key(signer.public_key, role)
    root.sign(signers["root"])
    _write_metadata(root_path, root)
    _publish_roles(offline_keys, online_keys, output_root, root)


def publish(offline_keys: Path, online_keys: Path, output_root: Path) -> None:
    root_path = output_root / "metadata" / "root.json"
    if not root_path.is_file():
        raise RuntimeError("No initialized root.json exists; run init first.")
    root = Metadata[Root].from_file(str(root_path))
    root.signed.verify_delegate("root", root.signed_bytes, root.signatures)
    if root.signed.is_expired(datetime.now(UTC)):
        raise RuntimeError("The TUF root is expired and must be rotated offline.")
    _publish_roles(offline_keys, online_keys, output_root, root)


def _publish_roles(
    offline_keys: Path, online_keys: Path, output_root: Path, root: Metadata[Root]
) -> None:
    metadata_dir = output_root / "metadata"
    target_dir = output_root / "targets"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    target_paths = _copy_targets(target_dir)

    targets_version = _next_version(metadata_dir / "targets.json", Targets)
    targets = Metadata(
        Targets(
            version=targets_version,
            expires=_expiry("targets"),
            targets={
                relative: TargetFile.from_file(relative, str(path), ["sha256"])
                for relative, path in target_paths.items()
            },
        )
    )
    targets.sign(_load_signer("targets", offline_keys, root))
    targets_bytes = targets.to_bytes()
    _atomic_write(metadata_dir / "targets.json", targets_bytes)

    snapshot_version = _next_version(metadata_dir / "snapshot.json", Snapshot)
    snapshot = Metadata(
        Snapshot(
            version=snapshot_version,
            expires=_expiry("snapshot"),
            meta={"targets.json": _meta(targets_version, targets_bytes)},
        )
    )
    snapshot.sign(_load_signer("snapshot", online_keys, root))
    snapshot_bytes = snapshot.to_bytes()
    _atomic_write(metadata_dir / "snapshot.json", snapshot_bytes)

    timestamp_version = _next_version(metadata_dir / "timestamp.json", Timestamp)
    timestamp = Metadata(
        Timestamp(
            version=timestamp_version,
            expires=_expiry("timestamp"),
            snapshot_meta=_meta(snapshot_version, snapshot_bytes),
        )
    )
    timestamp.sign(_load_signer("timestamp", online_keys, root))
    _atomic_write(metadata_dir / "timestamp.json", timestamp.to_bytes())


def _copy_targets(target_dir: Path) -> dict[str, Path]:
    sources = {
        "providers/index.json": REPOSITORY / "providers" / "index.json",
        "schema/provider-v1.schema.json": REPOSITORY
        / "schema"
        / "provider-v1.schema.json",
    }
    sources.update(
        {
            f"providers/{path.name}": path
            for path in sorted((REPOSITORY / "providers").glob("*.json"))
            if path.name != "index.json"
        }
    )
    copied: dict[str, Path] = {}
    for relative, source in sources.items():
        destination = target_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        copied[relative] = destination
    return copied


def _generate_signer(path: Path) -> CryptoSigner:
    signer = CryptoSigner.generate_ed25519()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(signer.private_bytes)
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return signer


def _load_signer(role: str, key_directory: Path, root: Metadata[Root]) -> CryptoSigner:
    keyids = root.signed.roles[role].keyids
    if len(keyids) != 1:
        raise RuntimeError(f"Expected exactly one configured {role} signing key.")
    key = root.signed.keys[next(iter(keyids))]
    path = key_directory / f"{role}.pem"
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise RuntimeError(f"Private {role} key is missing or has unsafe permissions.")
    return CryptoSigner.from_priv_key_uri(f"file2:{path}", key)


def _next_version(path: Path, role_type: type[Targets | Snapshot | Timestamp]) -> int:
    if not path.is_file():
        return 1
    metadata = Metadata.from_file(str(path))
    if not isinstance(metadata.signed, role_type):
        raise TypeError(f"Unexpected metadata role in {path.name}.")
    return metadata.signed.version + 1


def _meta(version: int, data: bytes) -> MetaFile:
    return MetaFile(version, len(data), {"sha256": hashlib.sha256(data).hexdigest()})


def _expiry(role: str) -> datetime:
    return datetime.now(UTC) + timedelta(days=ROLE_EXPIRY[role])


def _write_metadata(path: Path, metadata: Metadata[Root]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, metadata.to_bytes())


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    except Exception:
        Path(name).unlink(missing_ok=True)
        raise


def _require_external_key_directory(path: Path) -> None:
    repository = REPOSITORY.resolve()
    if path == repository or repository in path.parents:
        raise RuntimeError("Private TUF keys must be stored outside the repository.")


def _require_separate_key_directories(offline: Path, online: Path) -> None:
    if offline == online or offline in online.parents or online in offline.parents:
        raise RuntimeError(
            "Offline and online TUF keys must use separate directory trees."
        )


if __name__ == "__main__":
    raise SystemExit(main())
