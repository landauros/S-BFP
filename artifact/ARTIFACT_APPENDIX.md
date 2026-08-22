# Artifact Appendix: S-BFP

## Abstract

This artifact contains the implementation and de-identified evaluation material
for S-BFP, a stochastic challenge-response browser fingerprinting prototype. It
supports functional inspection of the Canvas and Web Audio workflows and
reproduces the retained stability rows and environment distribution reported in
paper Tables 2 and 3.

## Scope and claims

| Paper claim | Artifact evidence | Expected result |
| --- | --- | --- |
| Audio stability | `python scripts/reproduce_tables.py --verify-paper` | 206/206, 100.0% |
| Canvas stability | same command | 196/198, 99.0% |
| Cohort size and environment distribution | generated `results/table3_environments.csv` | 213 devices; rows match paper Table 3 |
| Stochastic browser workflow is executable | register in the web UI and run both panels | each panel renders repeated challenges and reports a hash-stability summary |
| Deterministic server challenge generation | automated test suite | repeated endpoint configuration is well formed and all routes pass |

The artifact does not claim to reproduce a production risk engine or to prove
security against every adaptive attacker. It also does not distribute the
restricted source collection.

## Hardware and software

- CPU: any x86-64 or ARM64 processor; two cores recommended.
- Memory: 1 GiB free.
- Disk: 300 MiB for a native environment or about 500 MiB for Docker.
- OS: Windows 10/11, current Linux, or current macOS.
- Native runtime: Python 3.11–3.13 and `pip`.
- Browser: current Chromium, Firefox, or Safari with Canvas and Web Audio.
- Optional: Docker Engine with Compose v2.

The aggregate reproduction is CPU-only and typically finishes in under one
minute. Interactive rendering usually takes several seconds per modality,
depending on the browser.

## Installation

From the artifact root, use one of:

```powershell
# Windows PowerShell
.\scripts\setup.ps1
.\scripts\run.ps1
```

```sh
# Linux/macOS
sh scripts/setup.sh
sh scripts/run.sh
```

or:

```sh
docker compose up --build
```

Open `http://127.0.0.1:5001/`. Native startup may open it automatically.

## Functional evaluation

1. Select Register and enter a pseudonymous username of 3–20 letters, digits, or
   underscores.
2. Read and affirm the consent notice. Save the generated password.
3. Acquire the test session when prompted.
4. Run Canvas and Audio. The panels perform five Canvas repetitions and ten
   Audio repetitions to match the collection configuration.
5. Confirm that every panel presents a completion message. Hardware differences
   may legitimately cause unstable hashes; this is an experimental outcome, not
   an execution failure.
6. Inspect the newly created record under the configured runtime data directory.
   With default settings it must not contain an IP address, full user-agent
   string, or raw Canvas fingerprint.

## Paper-table reproduction

Run:

```sh
python scripts/reproduce_tables.py --verify-paper
```

Expected terminal values are 206/206 Audio, 196/198 Canvas, and 213 environments,
followed by `Verified: the retained Audio/Canvas rows and Table 3 match the
paper.` CSV outputs appear in `results/`.

## Automated checks

```sh
python -m unittest discover -s tests -v
python scripts/verify_artifact.py dist/s-bfp-usenix-artifact.zip
```

The first command uses a temporary runtime directory. The second verifies that
the release bundle has required documents and no restricted/raw-data path.

## Data provenance and privacy

The released JSONL is a deterministic aggregation of the first collection
session for each of 213 participants. It contains only a new sequential ID,
coarse environment category, and per-modality availability/run/uniqueness/stable
values. Original IP addresses, user agents, usernames, timestamps, rendering
hashes, images, and passwords are omitted. See `ETHICS_AND_DATA.md`.

## Troubleshooting

- If port 5001 is occupied, set `S_BFP_PORT` to another local port.
- If the browser does not open, navigate to the printed local URL manually.
- If Docker cannot access the service, confirm the Compose port mapping and that
  `S_BFP_HOST=0.0.0.0` is present in `docker-compose.yml`.
