# S-BFP: Stochastic Browser Fingerprinting

Research artifact for **From Frozen Pose to Live Dance: Stochastic Browser
Fingerprinting for Robust Risk-Based Authentication**.

S-BFP is a Flask-based research prototype for server-controlled browser
fingerprinting challenges. It contains:

- a **Canvas** experiment that renders deterministic text at changing positions;
- a **Web Audio** experiment that renders deterministic oscillator snippets with
  configurable silent gaps;
- server-side challenge generation based on HMAC-DRBG;
- a derived 213-participant dataset and a script that reproduces the paper's
  stability and environment tables.

This is an experimental prototype, not a production authentication service.

## Requirements

- Python 3.11 or newer
- a current desktop browser with Canvas and Web Audio enabled

No GPU is required.

## Install and run

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

### Linux or macOS

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python app.py
```

Open <http://127.0.0.1:5001/> if it does not open automatically. Register with
a pseudonymous username, accept the consent notice, save the generated password,
and then run the Canvas and Audio panels.

New local runs are stored under `User_Manager/data/` by default.

## Reproduce the paper tables

The evaluator-facing dataset is `data/public/records.jsonl`. It contains coarse
environment categories and per-modality stability summaries, without the raw
rendering values or direct identifiers contained in the source collection.

```sh
python scripts/reproduce_tables.py --verify-paper
```

Expected summary:

```text
Table 1 - Stability
Audio  206/206 (100.0%)
Canvas 196/198 (99.0%)
Table 2 - Environment total: 213
Verified: Tables 1 and 2 match the paper.
```

CSV outputs are written to `results/table1_stability.csv` and
`results/table2_environments.csv`. Dataset fields are documented in
`data/public/README.md`.

Maintainers who hold the source collection can regenerate the derived dataset
with:

```sh
python scripts/make_public_dataset.py --input users --output data/public/records.jsonl
```

## Tests

```sh
python -m unittest discover -s tests -v
```

The tests use a temporary runtime directory and do not modify the retained
research records.

## Configuration

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `S_BFP_HOST` | `127.0.0.1` | Bind address |
| `S_BFP_PORT` | `5001` | HTTP port |
| `S_BFP_OPEN_BROWSER` | `1` | Open the local URL on startup |
| `S_BFP_DEBUG` | `0` | Flask debug mode |
| `S_BFP_DATA_DIR` | `User_Manager/data` | New runtime records |
| `S_BFP_SERVER_SECRET` | demonstration value | Challenge-generation secret |
| `S_BFP_SESSION_SECRET` | demonstration value | Flask session-signing secret |
| `S_BFP_STORE_CLIENT_METADATA` | `0` | Store IP/full user-agent when explicitly enabled |
| `S_BFP_STORE_RAW_FINGERPRINT` | `0` | Store raw fingerprint details when explicitly enabled |
| `S_BFP_MAX_UPLOAD_MIB` | `12` | Maximum request size |

For any network deployment, replace the demonstration secrets, enable TLS, and
review access and retention controls.

## Data handling

- `data/public/records.jsonl` is the derived dataset used by the reproduction
  script.
- `users/` contains retained source collection records and is not needed to run
  the application, tests, or paper-table reproduction.
- `Canvas/upload/` contains retained Canvas files from the original repository.
- Only `scripts/make_public_dataset.py` reads `users/`; it does not modify those
  source files.

The source records may contain direct or device-identifying fields and must be
handled according to the study's consent, ethics, access, and retention rules.

## Known limitations

- Results depend on the browser, audio stack, fonts, operating system, and
  hardware.
- The session coordinator is process-local and intended for one evaluator at a
  time.
- The prototype collects stability measurements; it does not implement a full
  production risk engine.
