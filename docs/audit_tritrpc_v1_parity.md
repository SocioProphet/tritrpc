# TritRPC v1 Repo Health + Parity Audit

Status: **Completed (post-fix)**. This report captures the protocol-relevant issues found
and the corrective actions taken.

## Findings (protocol-relevant)

| ID | Severity | Issue | Evidence | Status |
| --- | --- | --- | --- | --- |
| A1 | **High** | Rust envelope builder previously used zeroed `schema_id`/`context_id`, diverging from fixtures. | `rust/tritrpc_v1/src/lib.rs` now defines canonical constants and uses them in the envelope builder (L125-L193). | **Fixed** |
| A2 | **High** | Fixture verification did not assert full-frame byte equality or repack determinism. | Go fixture tests re-encode and compare full frames (`go/tritrpcv1/fixtures_test.go` L89-L102); Rust tests do the same (`rust/tritrpc_v1/tests/fixtures.rs` L81-L105). | **Fixed** |
| A3 | **Medium** | Go/Rust lacked structured envelope decoders; tests used ad-hoc field splits only. | Envelope decoders exist in Go (`go/tritrpcv1/envelope_decode.go` L24-L143) and Rust (`rust/tritrpc_v1/src/lib.rs` L219-L341). | **Fixed** |
| A4 | **Medium** | Path-A Avro subset had no decode/round-trip checks. | HGRequest/HGResponse decoders/encoders added in Go (`go/tritrpcv1/avrodec.go` L1-L321) and Rust (`rust/tritrpc_v1/src/lib.rs` L563-L844) with round-trip tests (`go/tritrpcv1/fixtures_test.go` L129-L153; `rust/tritrpc_v1/tests/fixtures.rs` L131-L147). | **Fixed** |
| A5 | **Medium** | Spec/docs claimed MAC fallback, rolling nonces, and AUX structures were supported across ports. | Spec/docs now reflect current port behavior (`spec/README-full-spec.md` L7-L23; `docs/THEORY.md` L70-L94). | **Fixed** |
| A6 | **Low** | README referenced CI/repack-check jobs that did not exist. | Added `Makefile` + CI workflow and updated README (`Makefile` L1-L20; `.github/workflows/ci.yml` L1-L27; `README.md` L106-L120). | **Fixed** |
| A7 | **Low** | Tag comparisons used direct equality; constant-time compare was missing. | Constant-time comparisons now used in Go/Rust fixture checks (`go/tritrpcv1/fixtures_test.go` L117-L122; `rust/tritrpc_v1/tests/fixtures.rs` L123-L125). | **Fixed** |

## Scope checklist coverage

- **A) Cross-language envelope parity:** Schema/context constants aligned; AAD definition enforced.
- **B) Strict fixture verification completeness:** Full-frame repack checks added and required.
- **C) Decoder symmetry / round-trip reliability:** HGRequest/HGResponse decode → encode checks added for Path‑A fixtures.
- **D) Spec alignment and missing normative text:** Spec/docs updated to match port behavior (no MAC fallback, explicit nonces, AUX opaque).
- **E) Cryptography invariants:** Tag size + nonce size checked; constant-time tag comparison enforced in verification.
- **F) Tooling / CI ergonomics:** Added `make verify` and CI workflow.
