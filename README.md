# Ventoy Depot Registry

Curated, declarative provider metadata for [Ventoy Depot](https://github.com/unfortunatelyalex/ventoy-depot).
Provider files contain JSON data only and cannot execute code.

This repository is intentionally separate from the application so curated providers can
be updated independently. Published targets will be protected by The Update Framework
(TUF). Until the initial offline root and the separated signing roles have been
provisioned, the application must continue using its bundled provider data.

## Trust and publishing

- Root keys are generated and stored offline, never in this repository or GitHub.
- Targets keys are kept separate from snapshot and timestamp publishing keys.
- Only short-lived snapshot/timestamp publishing credentials may be GitHub secrets.
- Root, targets, snapshot and timestamp expire after 365, 90, 30 and 14 days.
- Publishing refuses to deploy unless all four TUF roles and generated targets exist.

Run `python scripts/validate_registry.py` before submitting a provider. Fixtures must
contain both matching and non-matching filenames. Downloads must be free, public,
official, HTTPS-only, checksum verified and bound to explicit variants.

## Curated providers

The initial registry contains Arch Linux, Ubuntu, Debian, Fedora, Linux Mint,
EndeavourOS, CachyOS, Clonezilla Live, GParted Live, Kali Linux, NixOS, Omarchy,
Manjaro, Pop!_OS, Nobara, SystemRescue, Vanilla OS, Windows 11 and Zorin OS.
Every provider declares its products, variants, architectures and channels. Detection
rules map captured filename fields into a stable identity and are exercised by shared
positive and negative fixtures.

`automatic_download: false` and `downloadable: false` are security boundaries, not UI
hints. In particular, Zorin OS Pro media is recognized but never acquired. Manjaro
preview images require an explicit persisted mapping because their filenames do not
reliably encode the channel.

Verification is deliberately conservative: a source is marked `SIGNED` only when a
full, stable publisher fingerprint is available from an official source. The presence
of a `.sig` file alone is insufficient. See [provider source notes](docs/provider-sources.md).

## Manifest contract

- `allowed_hosts` applies to metadata, downloads, checksums, signatures and every
  redirect hop.
- `release_sources` describe how a generic driver discovers and verifies artifacts.
- `detection` is filename-only and contains no executable code. `$group:name` copies a
  named regular-expression group into an identity field.
- SHA-256 is the minimum accepted checksum. `SIGNED` additionally requires a full
  pinned OpenPGP fingerprint.
- The validator rejects non-HTTPS URLs, non-allow-listed URL hosts, local/private IP
  literals, path traversal, weak checksums, short fingerprints, ambiguous fixtures and
  cross-provider fixture collisions.

Ventoy Depot is not affiliated with, endorsed by, or supported by the Ventoy project.
