# Open Science appendix draft

Replace bracketed placeholders before submission. The paper appendix should list
every artifact and its access path rather than only a single generic link.

## Artifacts

1. **S-BFP source artifact.** An anonymized repository containing the Flask
   implementation, Canvas/Audio/WebGL browser experiments, HMAC-DRBG challenge
   generator, pinned dependencies, container configuration, and automated tests.
   Anonymous review access: `[ANONYMOUS_ARTIFACT_URL]`. Permanent camera-ready
   archive: `[VERSIONED_DOI]`.
2. **De-identified evaluation dataset.** A JSON Lines file with 213 participant
   summaries containing coarse environment categories and modality stability
   aggregates, with no raw fingerprints or direct identifiers. It is included in
   the same archive under `data/public/records.jsonl`.
3. **Evaluation scripts.** `scripts/reproduce_tables.py` regenerates Tables 2 and
   3 and checks the reported values. `scripts/build_artifact.py` and
   `scripts/verify_artifact.py` construct and audit the release bundle.
4. **Documentation.** `README.md` provides setup and experiment instructions;
   `artifact/ARTIFACT_APPENDIX.md` maps paper claims to evaluation steps; and
   `ETHICS_AND_DATA.md` documents data minimization and omissions.

## Omitted material

Original per-participant collection records are not publicly released because
they contain IP addresses, full user-agent strings, timestamps, raw rendering
material, and device-level hashes. These records are not needed to reproduce the
published aggregate tables; the released derived dataset supports those checks.
Any controlled access statement must be added only if the authors can actually
provide a compliant access process.
