# TritRPC v1 Theory (Conceptual Model)

This document captures the conceptual and mathematical ideas that underpin the TritRPC v1
protocol. It is intentionally verbose so that the theory is available alongside the
implementation details in this repository.

## 1. Trits and base-3 representation

TritRPC models some data using **trits**, the ternary analogue of bits. A trit has three
possible values: `0`, `1`, or `2`. Representing data in base-3 can be useful for protocols
or domains that want ternary-native encodings, compactness for ternary symbols, or explicit
distinction of three-state logic.

Trits are still carried over bytes. The protocol defines a canonical mapping so that binary
transport remains deterministic and independent of platform endianness.

## 2. TritPack243 (packed trits in bytes)

The **TritPack243** scheme packs trits into bytes using base-3 arithmetic:

- Five trits can be packed into a single byte because `3^5 = 243`, which fits in one byte.
- A single packed byte therefore represents a 5-trit group as a base-3 integer in the range
  `0..242`.
- If the total number of trits is not a multiple of five, TritPack243 emits a **tail marker**
  byte in the range `243..246` indicating how many trits follow (1–4), plus one extra byte
  containing those trailing trits encoded as a base-3 integer.
- Bytes in the range `247..255` are invalid in canonical output.

This packing is deterministic and is used by other encoding layers in the protocol, such as
TLEB3.

## 3. TLEB3 (ternary length encoding)

TLEB3 is the protocol's **length encoding** scheme. It encodes non-negative integers using
base-9 digits, which are themselves carried as trits:

- An integer `n` is written in base-9 as digits `d0, d1, ...` (least significant first).
- Each digit is stored as a **tritlet**: `C, P1, P0`, where `P1:P0` (two trits) represent a
  value `0..8`, and `C` is a continuation trit (`2` = more digits follow, `0` = final digit).
- These trits are concatenated and then packed using TritPack243.

The combination of base-9 digits and TritPack243 allows lengths to be encoded compactly and
unambiguously over byte streams.

## 4. Envelope model

Every TritRPC frame is built as an **envelope** that separates routing metadata from the
payload and integrity layer. The envelope has multiple logical regions:

1. **SERVICE and METHOD identifiers** (routing keys)
2. **AUX structures** (optional, used for traces, signatures, or Proof-of-Execution)
3. **Payload** (user-defined or service-defined data)
4. **AEAD lane** (authentication tag or full authenticated encryption)

The reference implementation models these pieces explicitly and uses them to produce canonical
fixture vectors.

## 5. Path-A vs Path-B

TritRPC v1 defines multiple profiles for payload encoding:

- **Path-A**: Uses Avro Binary Encoding for payloads. This is the main path exercised in the
  reference implementation and fixture vectors.
- **Path-B**: Uses ternary-native encodings (e.g., TLEB3 lengths and balanced-ternary integers)
  and is currently represented by a smaller “toy subset” of fixtures in `fixtures/`.

Path-B remains compatible with the same envelope and AEAD structure; only the payload encoding
changes.

## 6. AEAD and integrity layer

The protocol authenticates frames using an **AEAD lane**:

- The preferred suite in the reference implementation is **XChaCha20-Poly1305**.
- Some fixtures allow a deterministic MAC fallback when AEAD primitives are not available.
- The AEAD tag is computed over the envelope's AAD (associated data) and the payload, using
  a 24-byte nonce. This makes integrity checks deterministic and replay-resistant.

A strict verification mode is used by fixtures and tooling to ensure tags remain correct if
any portion of the envelope or payload changes.

## 7. Streaming and rolling nonces

For streaming sequences of frames, TritRPC uses **rolling nonces**:

- A base nonce is derived or agreed upon.
- Each subsequent frame increments or derives the next nonce in a deterministic way.
- This keeps AEAD authentication safe across a stream while retaining deterministic test
  fixtures.

## 8. AUX structures

AUX structures are optional fields that can be inserted into an envelope for additional
metadata. The reference implementation includes:

- **Trace**: tracing and correlation metadata
- **Sig**: placeholder for signature material
- **PoE (Proof-of-Execution)**: a strict-initial placeholder for execution proofs

These are designed to be extensible so that additional metadata can be added without breaking
existing envelope parsing.

## 9. Hypergraph service model

The repository ships a reference **hypergraph service** for example RPCs and fixture
generation. Its payloads are encoded using Avro (Path-A) and are meant to be canonical and
stable across Rust and Go implementations.

Examples include vertex and hyperedge creation, with payload schemas that are encoded
deterministically and verified in fixture tests.

## 10. Determinism as a design goal

A recurring theme in TritRPC is determinism:

- **Canonical encodings** for trits, lengths, and payloads
- **Stable fixture vectors** to ensure cross-language reproducibility
- **Strict verification** that rejects any non-canonical or malformed encoding

This determinism is what makes the repository's fixture verification and repack tests
meaningful: every language implementation should produce identical bytes for the same
semantic input.

## Further reading

- Full specification: `spec/README-full-spec.md`
- Reference implementation: `reference/tritrpc_v1.py`
- Fixtures: `fixtures/`
