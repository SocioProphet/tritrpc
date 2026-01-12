# TritRPC v1 Integration Readiness Checklist

This checklist documents the **minimum verification steps** required before integrating a
policy/view (permissions + privacy) AUX bundle. It reflects the current behavior of the
Go/Rust ports and fixtures.

## ✅ Protocol invariants (must hold)

- Schema/context IDs are canonical and match fixtures.
- AEAD tags are computed with **empty plaintext** and **AAD = envelope bytes before the tag
  field** (payload + AUX included).
- Fixtures are the source of truth; repacking must reproduce **identical bytes**.
- Nonces are deterministic and pulled from `fixtures/*.nonces`.

## ✅ Local verification (single command)

Run from repo root:

```bash
make verify
```

This runs:
- Rust format check + tests
- Go format check + tests
- Fixture AEAD verification script

## ✅ Per-language commands (if running manually)

```bash
cd rust/tritrpc_v1
cargo fmt --check
cargo test
```

```bash
cd go/tritrpcv1
gofmt -l .
go test
```

```bash
python tools/verify_fixtures_strict.py
```

## ✅ Readiness gates

- All commands above must succeed on a clean checkout.
- Fixture repack tests must pass (full-frame byte equality).
- Envelope decode → encode stability holds for HGRequest/HGResponse Path-A payloads.
