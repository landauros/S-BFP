# Public evaluation dataset

`records.jsonl` contains 213 de-identified participant summaries, one JSON object
per line. It is sufficient to reproduce paper Tables 2 and 3.

Schema:

```json
{
  "participant_id": "P0001",
  "environment": {"os": "Windows", "browser": "Chrome"},
  "modalities": {
    "audio": {"available": true, "runs": 10, "unique_results": 1, "stable": true},
    "canvas": {"available": true, "runs": 5, "unique_results": 1, "stable": true},
    "webgl": {"available": true, "runs": 10, "unique_results": 1, "stable": true}
  }
}
```

The summary uses each participant's first collection session, matching the cohort
snapshot reported in the paper. A modality with no submitted session has
`available: false`, zero runs, zero unique results, and `stable: false`.

No original identifier or rendering value is included. In particular, this file
contains no username, password material, IP address, full user-agent string,
timestamp, rendering hash, seed, image, or audio sample.
