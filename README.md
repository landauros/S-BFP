# S-BFP: Stochastic Browser Fingerprinting

Research artifact for **From Frozen Pose to Live Dance: Stochastic Browser
Fingerprinting for Robust Risk-Based Authentication**.

S-BFP turns a static browser fingerprint into a server-controlled,
challenge-response measurement. A deterministic random bit generator (DRBG)
derives device-specific rendering primitives from the preliminary fingerprint,
while a second session-dependent input changes their spatial arrangement. The
prototype evaluates three browser surfaces:

- **Canvas** — deterministic text content with session-varying positions;
- **Web Audio** — deterministic oscillator configurations and waveform hashes;
- **WebGL** — deterministic colored triangles with session-varying rendering.

The browser renders each challenge repeatedly, hashes the result, and sends the
stability outcome to the Flask server. The research goal is to make replay of a
previously captured static fingerprint less useful in risk-based authentication.

> This is a research prototype, not a production authentication service. The
> default secrets are public demonstration values, and the in-process exclusive
> session lock is intended for a single evaluator.

## Artifact status

This repository is organized for USENIX Security '26 artifact evaluation:

- one obvious entry point (this README);
- pinned Python dependencies and Python 3.11–3.13 support;
- native Windows and POSIX setup/run scripts;
- a Docker configuration for a reproducible service environment;
- automated application tests;
- a de-identified dataset and scripts that reproduce paper Tables 2 and 3;
- a self-contained artifact appendix and Open Science statement draft;
- an explicit data/ethics statement and a release-archive verifier.

Final publication still requires the authors to choose licenses and replace the
access placeholders with the anonymous-review URL and permanent archive DOI.

## Repository map

| Path | Purpose |
| --- | --- |
| `app.py` | Flask application, registration/login, test-session coordination, and result collection |
| `drbg.py` | HMAC-DRBG implementation used for deterministic challenge generation |
| `Audio/` | Web Audio challenge generator and browser experiment |
| `Canvas/` | Canvas text generator, renderer upload, cropping, and hashing |
| `Webgl/` | WebGL triangle generator, renderer upload, cropping, and hashing |
| `User_Manager/` | Per-user local persistence for newly collected demo results |
| `data/public/` | De-identified, release-safe evaluation records |
| `scripts/` | Setup, launch, reproduction, packaging, and verification tools |
| `tests/` | Server route, consent, authentication, persistence, and modality tests |
| `artifact/` | Evaluation roadmap and submission text drafts |

## Quick start (native)

Requirements: Python 3.11 or newer and a current desktop browser with Canvas,
Web Audio, and WebGL enabled. No GPU is required; software WebGL is sufficient.

### Windows PowerShell

```powershell
Set-Location D:\a800\S-BFP
.\scripts\setup.ps1
.\scripts\run.ps1
```

### Linux or macOS

```sh
cd /path/to/S-BFP
sh scripts/setup.sh
sh scripts/run.sh
```

Open <http://127.0.0.1:5001/> if the browser does not open automatically.
Choose **Register**, enter a pseudonymous username, read and accept the consent
notice, and save the generated password. After the session is acquired, run the
Canvas, Audio, and WebGL panels. A successful modality ends with a stability
summary and stores a local record under `User_Manager/data/users/`.

## Quick start (Docker)

```sh
docker compose up --build
```

Then open <http://127.0.0.1:5001/>. Runtime records are kept in the named
`s-bfp-data` volume and are not copied into the image.

## Reproduce paper results

The public dataset contains one row per participant with only a pseudonymous
artifact ID, coarse OS/browser categories, and per-modality run counts,
uniqueness counts, and stability booleans. It contains no raw rendering hashes,
images, usernames, IP addresses, full user-agent strings, timestamps, or
password material.

```sh
python scripts/reproduce_tables.py --verify-paper
```

Expected output:

```text
Audio  206/206 (100.0%)
Canvas 196/198 (99.0%)
WebGL  177/193 (91.7%)
Environment total: 213
Verified: Tables 2 and 3 match the paper exactly.
```

CSV versions are written to `results/table2_stability.csv` and
`results/table3_environments.csv`. The scripts deliberately summarize the first
collection session for each participant, which is the cohort snapshot used by
the paper tables.

The repository maintainer can regenerate the public file from the locally held
restricted records with:

```sh
python scripts/make_public_dataset.py --input users --output data/public/records.jsonl
```

Evaluators do not need, and should not receive, the restricted `users/` source
directory.

## Tests

```sh
python -m unittest discover -s tests -v
```

The suite uses an isolated temporary data directory. It does not read or mutate
the restricted research records.

## Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `S_BFP_HOST` | `127.0.0.1` | Bind address |
| `S_BFP_PORT` | `5001` | HTTP port |
| `S_BFP_OPEN_BROWSER` | `1` | Open the local URL on startup |
| `S_BFP_DEBUG` | `0` | Flask debug mode; keep disabled for evaluation |
| `S_BFP_DATA_DIR` | `User_Manager/data` | Runtime record directory |
| `S_BFP_SERVER_SECRET` | public demo value | Root key for modality-specific challenge secrets |
| `S_BFP_SESSION_SECRET` | public demo value | Flask session signing key |
| `S_BFP_STORE_CLIENT_METADATA` | `0` | Opt-in storage of IP and full user-agent metadata |
| `S_BFP_STORE_RAW_FINGERPRINT` | `0` | Opt-in storage of raw fingerprint strings/details |
| `S_BFP_MAX_UPLOAD_MIB` | `12` | Maximum request body size |

For any network deployment, set long random server and session secrets, put the
service behind TLS and an authenticated reverse proxy, and review the local data
retention policy. The demo defaults intentionally minimize newly collected data.

## Data and ethics

The repository's original research collection is restricted because it contains
fields that can directly or indirectly identify participants. It is excluded
from Docker images and release archives. See [ETHICS_AND_DATA.md](ETHICS_AND_DATA.md)
for the field-level policy and [data/public/README.md](data/public/README.md) for
the released schema.

The registration UI now requires affirmative consent. New runs do not retain IP
addresses, full user-agent strings, or raw rendered fingerprints unless the
maintainer explicitly enables the corresponding environment variables.

## Known limitations

- WebGL is measurably less stable than Audio and Canvas across environments; the
  paper reports 91.7% stability for the evaluated cohort.
- Results depend on browser, graphics/audio stack, fonts, and hardware. Container
  execution reproduces the server, not the evaluator's browser rendering stack.
- The current session coordinator is process-local and supports one active user;
  it is not appropriate for a multi-worker production deployment.
- The prototype demonstrates challenge generation and stability collection. It
  does not implement a complete account risk engine or production login policy.

## Release and citation

Use `python scripts/build_artifact.py` to create a deterministic, sanitized
archive, then `python scripts/verify_artifact.py dist/s-bfp-usenix-artifact.zip`
to verify its contents. The archive excludes the restricted source data and all
runtime records.

Before submission, complete every item in [artifact/RELEASE_CHECKLIST.md](artifact/RELEASE_CHECKLIST.md).
Citation metadata is intentionally deferred until author identities can be
disclosed. Add `CITATION.cff` to the camera-ready artifact.

## License

No license was present in the original repository. The authors must explicitly
select and add licenses before public archival; see [LICENSES.md](LICENSES.md).
Absence of a license means no reuse permission should be inferred.
