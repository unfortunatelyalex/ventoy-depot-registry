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

Ventoy Depot is not affiliated with, endorsed by, or supported by the Ventoy project.

