# Stockfish, bundled

`stockfish-linux-x86-64` is the official **Stockfish 19** release for Linux
x86-64, unchanged, so every deploy carries the engine and no request ever waits
on a download.

| | |
|---|---|
| Release | github.com/official-stockfish/Stockfish/releases/tag/sf_19 |
| Archive | `stockfish-linux-x86-64-universal.tar.gz`, SHA-256 `9defc0d4e55d49c65a6d042f3e571a39fcea499ade6dbe741b53b8c65e03611f` (as published) |
| Binary | `stockfish/stockfish-linux-x86-64-universal`, SHA-256 `0f83d24cc46d2c66c60f16001af5444873bc112b7d028594513426894c12da19` |
| Needs | glibc (libc, libm) only; runs on Amazon Linux 2023, the base of Vercel's Python runtime |
| Licence | GPL-3.0; source at the release above |

Tested 2026-10-22 in an Amazon Linux 2023 x86-64 container: `bench` signature
**2,497,913** nodes, the same as the Stockfish 19 calibration v2 was fitted on
(agents/chess/priors.py), and the brain's own searches (MultiPV, searchmoves,
depths 4-16) produced byte-identical output on both. Same engine, same
analyses, same agents.

To change it: bump `RELEASE` in agents/engines.py, run
`python -m agents.engines update-bundled`, re-run that comparison, then
`python -m agents.engine_parity` - a different engine may want a re-fit
(agents/calibration.py).
