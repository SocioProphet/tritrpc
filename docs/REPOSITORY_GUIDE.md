# Repository Guide (Pedantic)

This guide explains the structure of the repository and the intent behind each major
folder. It complements the top-level README by giving concrete navigation hints.

## Top-level layout

- `README.md`: Project summary, build instructions, and high-level navigation.
- `docs/`: Conceptual and procedural documentation.
  - `THEORY.md`: Theory and conceptual model for TritRPC v1.
  - `integration_readiness_checklist.md`: Pre-integration verification checklist.
  - `REPOSITORY_GUIDE.md`: This file.
- `spec/`: Specification material.
  - `README-full-spec.md`: The full spec text (repo copy).
  - `salad/`: Supporting artifacts for the spec (schemas, adjunct docs, etc.).
- `reference/`: Reference implementation used to generate fixture vectors.
  - `tritrpc_v1.py`: Reference pack/parse and encoding logic.
- `fixtures/`: Canonical fixture vectors used for verification tests.
  - `*.txt`: Hex vectors (canonical frames).
  - `*.nonces`: Per-line nonces aligned with fixtures for AEAD verification.
  - `jcs_blake3_vectors.json`: JCS canonical JSON + BLAKE3 hash vectors for receipt/content hashing.
- `rust/`: Rust implementation of TritRPC v1.
- `go/`: Go implementation of TritRPC v1.
- `scripts/`: Utility scripts (e.g., pre-commit hook install).
- `tools/`: Maintenance utilities (e.g., fixture or AEAD tag regeneration).

## Implementations

### Rust

The Rust implementation is organized under `rust/` and is validated through the fixture
vectors. It contains:

- Core encoding/decoding logic for TritRPC v1.
- CLI tooling to pack frames, verify fixtures, and inspect envelopes.
- Tests that enforce deterministic outputs.

### Go

The Go implementation lives under `go/` and mirrors the Rust functionality. It focuses on:

- Byte-for-byte parity with fixtures.
- CLI tools and verification routines.
- Integration of the same encoding theory as the Rust version.

## Reference implementation and fixtures

The reference Python code in `reference/tritrpc_v1.py` is the canonical generator used to
produce the fixture vectors. Fixtures are the **source of truth** for interoperability:

- Both Rust and Go tests re-encode frames and compare outputs to fixture bytes.
- Nonces are stored alongside fixtures to ensure AEAD tags can be re-computed and validated.

## How to navigate the spec

For normative requirements, start with:

- `spec/README-full-spec.md` — the full spec text.

This repository's code and tests should be read as an implementation of that specification.
The spec defines how the envelope layout, encoding schemes, AEAD lane, and negotiation flows
are expected to behave.

## Reproducibility and determinism checklist

When working in this repository, these expectations should always hold:

- A given logical frame should encode to a stable, identical byte sequence in Rust and Go.
- Fixtures should never change except when protocol rules change (and then only with
  regenerated tags).
- Any non-canonical encodings should be rejected by decoders.

If you modify encoding rules or envelope layout, you must regenerate fixtures and ensure
all tests still pass.
