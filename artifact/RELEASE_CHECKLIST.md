# USENIX Security '26 artifact release checklist

## Before paper submission / anonymous review

- [ ] Create a clean anonymous repository or archive; remove author identities
  and repository-owner metadata where anonymity is required.
- [ ] Confirm that `users/`, runtime data, logs, and raw uploads are absent.
- [ ] Run unit tests and `scripts/reproduce_tables.py --verify-paper`.
- [ ] Build and verify the sanitized ZIP.
- [ ] Add the anonymous artifact URL to `OPEN_SCIENCE.md` and the paper appendix.
- [ ] Reconcile the paper ethics language with actual source-data retention.

## Artifact evaluation

- [ ] Put an artifact appendix PDF in the submission, based on
  `artifact/ARTIFACT_APPENDIX.md`.
- [ ] State hardware/software requirements and estimated evaluation time.
- [ ] Map each requested badge/claim to exact commands and expected output.
- [ ] Test from a freshly extracted archive on at least Windows and Linux or Docker.
- [ ] Decide whether to request Available only, Functional, and/or Reproduced.

## Camera-ready / permanent availability

- [ ] Obtain all rights-holder approval and add code/data licenses.
- [ ] Add non-anonymous author and citation metadata (`CITATION.cff`).
- [ ] Deposit the exact release in a permanent archive such as Zenodo and reserve
  a DOI; do not use only a mutable GitHub/GitLab URL for the Available badge.
- [ ] Replace `[VERSIONED_DOI]` and other placeholders in all documents and paper.
- [ ] Record the immutable artifact version/commit and SHA-256 checksum.
- [ ] Confirm the DOI resolves without authentication and the archive is complete.
