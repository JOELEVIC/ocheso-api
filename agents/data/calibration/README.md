# What the agents were calibrated on

Carried over from the retired `ocheso` monorepo (tools/agents-data), so every
fit can be checked or re-run from this repository.

| File | What it is |
|---|---|
| `aggregates-2026-09.json.gz` | 5,854,382 rated Lichess games (September 2026, streamed): think-time tallies by rating band, cadence, move number and clock; mistake tallies; a reservoir of 20,000 real positions with the move played and the clock. `agents/data/think_v1.json` is distilled from it. |
| `fit-v1.json.gz` | Calibration v1 (`PRIORS_V1`): fitted on 2,003 of those positions as Stockfish 18 lite (WASM) and onnxruntime-web saw them (`agents/golden/analysed.jsonl.gz`). |
| `fit-v2-native.json.gz` | Calibration v2 (`PRIORS_V2`, what agents play with): the same positions as native Stockfish 19 and onnxruntime see them (`agents/golden/native-*.jsonl.gz`), fitted by `python -m agents.calibration fit`. The shipped knots keep the fit's own 200 knot (`B` in the comparison that chose them). |
| `gauge-v0-100.json.gz` | The difficulty gauge against 100 rated Lichess puzzles: correlation 0.54, easier than puzzle ratings (expected: puzzle ratings run above game ratings). |
| `puzzles-validation.json` | 1,685 Lichess puzzles stratified by rating, the gauge's yardstick. |

Maia's conformance with lc0 is `agents/golden/maia-conformance.json` (52 positions, within 0.06%).

Re-analysing after an engine change:

    python -m agents.calibration analyse native-train.jsonl.gz train
    python -m agents.calibration analyse native-heldout.jsonl.gz held-out
    python -m agents.calibration fit native-train.jsonl.gz native-heldout.jsonl.gz --samples 32
    python -m agents.engine_parity 1006 8

The Lichess streaming, think-time fit and puzzle sampling tools are TypeScript
and still live in `cca/tools/house-data`.

## Sources and licences

- **Lichess open database** - database.lichess.org, public domain (CC0).
- **Maia** - CSSLab, GPL-3.0 (github.com/CSSLab/maia-chess, v1.0), converted to ONNX with lc0 0.32.1; in `agents/models/maia`.
- **Stockfish** - GPL-3.0; not shipped here, fetched or installed at runtime (`agents/engines.py`).
