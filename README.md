# TritRPC v1 (Repository)

**Description:** TritRPC v1 is a deterministic, ternary-native RPC protocol with
authenticated envelope framing, reference fixtures, and Rust/Go implementations.

**Topics:** ternary, rpc, protocol, deterministic-encoding, fixtures, rust, go, avro, aead

This repository contains reference material, fixtures, and two language ports (Rust and Go)
for **TritRPC v1**, a protocol that blends ternary-native encodings with conventional
byte-transport, along with authenticated envelope framing. The focus of this repo is
**deterministic, byte-for-byte reproducibility** across implementations.

## Quick navigation

- **Theory & conceptual model:** `docs/THEORY.md`
- **Full specification:** `spec/README-full-spec.md`
- **Reference implementation:** `reference/tritrpc_v1.py`
- **Integration readiness checklist:** `docs/integration_readiness_checklist.md`
- **Fixtures (canonical vectors):** `fixtures/`
- **Rust port:** `rust/`
- **Go port:** `go/`

## What this repository guarantees

1. **Canonical encoding:** Trits, lengths, payloads, and envelopes encode to a canonical
   byte sequence.
2. **Cross-language parity:** Rust and Go implementations produce identical bytes for
   the same semantic input.
3. **Strict verification:** Fixtures and tests reject any non-canonical or malformed
   outputs.
4. **Traceable theory:** The theory and spec are included in-repo and linked here for
   easy, long-term reference.

## Theory at a glance (summary)

TritRPC v1 is built on these conceptual layers:

- **Trits (base-3 digits)** are packed into bytes using **TritPack243**, which encodes
  5 trits per byte and uses a tail marker for 1–4 trailing trits.
- **TLEB3** encodes lengths as base-9 digits expressed as tritlets, then packs those
  trits via TritPack243.
- **Envelope framing** separates routing metadata (SERVICE + METHOD), AUX structures,
  payload bytes, and the AEAD authentication lane.
- **Path-A** payloads are encoded with Avro Binary Encoding (used by the reference
  implementation and most fixtures).
- **Path-B** payloads are ternary-native (toy subset fixtures demonstrate this).
- **AEAD integrity** uses XChaCha20-Poly1305 with 24-byte nonces for authenticated frames.

For complete detail, read `docs/THEORY.md` and the full spec.

## Repository layout

A more detailed guide lives in `docs/REPOSITORY_GUIDE.md`. At a glance:

- `docs/`: Theory and repository guide.
- `spec/`: Full specification (normative requirements).
- `reference/`: Python reference implementation and fixture generator.
- `fixtures/`: Canonical hex fixtures and their nonce files.
- `rust/`, `go/`: Language implementations.
- `scripts/`, `tools/`: Utility scripts and regeneration tooling.

## Build and test (ports)

### Build the ports

- Rust: `cd rust/tritrpc_v1 && cargo test`
- Go: `cd go/tritrpcv1 && go test`

### Fixture verification

- Rust: `cargo test -p tritrpc_v1` validates AEAD tags, schema/context IDs, and full-frame
  repack determinism using `.nonces`.
- Go: `cd go/tritrpcv1 && go test` performs the same validations.

### CLI tools

- Rust:
  ```bash
  cargo run -p tritrpc_v1 --bin trpc -- pack \
    --service hyper.v1 \
    --method AddVertex_a.REQ \
    --json payload.json \
    --nonce <hex> \
    --key <hex>
  ```
- Go:
  ```bash
  cd go/tritrpcv1/cmd/trpc
  go build
  ./trpc verify --fixtures ../../fixtures/vectors_hex_unary_rich.txt \
    --nonces ../../fixtures/vectors_hex_unary_rich.txt.nonces
  ```

## Fixtures and determinism

Fixtures are the **interoperability contract** between implementations. The reference
implementation generates canonical frames in `fixtures/*.txt`, and both Rust and Go
implementations must reproduce those bytes exactly. Each fixture line has a paired nonce
file (`*.nonces`) used to recompute AEAD tags.

## Path-B (ternary) vectors (toy subset)

See `fixtures/vectors_hex_pathB.txt` (+ `.nonces`). These use ternary-native encodings
(TLEB3 lengths, balanced-ternary ints) and are AEAD-authenticated like Path-A.

## CI

A GitHub Actions workflow runs `make verify` (format checks + tests + fixture verification)
on push/PR.

## Release workflow

- On tag push (`v*`), builds Rust + Go CLIs, zips them with fixtures, and attaches
  them to the GitHub Release.
- See `.github/workflows/release.yml`.

## Repack check

Repack determinism is verified in the fixture tests by re-encoding envelopes and comparing
full-frame bytes to fixture vectors.

## Pre-commit hook (strict AEAD verification)

To prevent committing drifted fixtures, enable the pre-commit hook that re-computes
**XChaCha20-Poly1305** tags for every `fixtures/*.txt` line using the paired `.nonces`:

```bash
pip install cryptography   # required for local verification
bash scripts/install_hooks.sh
# try a commit; it will refuse if any tag mismatches its AAD+nonce
```

If you need to refresh tags intentionally, run:

```bash
python tools/regenerate_aead_tags.py
```
