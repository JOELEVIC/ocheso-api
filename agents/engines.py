"""
The engines the brain asks: Stockfish for search, Maia for "what would a person
at this rating play".

Stockfish runs as a UCI child process and is read the brain's way - every
depth, every MultiPV line, indexed by move (the same parsing as calibration's).
Maia runs through onnxruntime on the same ONNX weights calibration used, one
session per rating band, loaded on first use.

Where Stockfish comes from, first found wins: STOCKFISH_PATH; `stockfish` on
the PATH; the official Stockfish 19 build for this machine, fetched once per
instance into the temp directory and checked against its published SHA-256
before it is unpacked (serverless hosts have no package manager, and a 100 MB
binary has no place in git). The priors were fitted on Stockfish 19
(agents/chess/priors.py): `Stockfish.name` says what is really running, and
`health()` reports it.

Maia lives in MAIA_DIR (default: agents/models/maia, files maia-<band>.onnx).
If it is missing the brain falls back to its board heuristic - weaker, and
reported as priorSource "heuristic" on every decision, so it never happens
silently.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import urllib.request
from pathlib import Path
from typing import Optional

from agents.chess.maia import MAIA_PLANES, maia_history, maia_input, maia_policy

DEFAULT_MAIA_DIR = Path(__file__).parent / "models" / "maia"

# The engine the priors were fitted on.
STOCKFISH_VERSION = "Stockfish 19"
_RELEASE = "https://github.com/official-stockfish/Stockfish/releases/download/sf_19/"
STOCKFISH_BUILDS = {
    ("Linux", "x86_64"): (_RELEASE + "stockfish-linux-x86-64-universal.tar.gz",
                          "9defc0d4e55d49c65a6d042f3e571a39fcea499ade6dbe741b53b8c65e03611f"),
    ("Linux", "aarch64"): (_RELEASE + "stockfish-linux-arm64-universal.tar.gz",
                           "fe26cfd1d9db4c8af3d21e24d9ff34cacb31c1f940085a7583da11796f2bac01"),
    ("Darwin", "arm64"): (_RELEASE + "stockfish-macos-universal.tar.gz", None),
}
_fetch_lock = threading.Lock()


def stockfish_path(fetch: bool = True) -> Optional[str]:
    configured = os.environ.get("STOCKFISH_PATH")
    if configured:
        return configured
    found = shutil.which("stockfish")
    if found or not fetch:
        return found
    return fetch_stockfish()


def fetch_stockfish(directory: Optional[Path] = None) -> Optional[str]:
    """The official build for this machine, downloaded and verified once."""
    build = STOCKFISH_BUILDS.get((platform.system(), platform.machine()))
    if not build or not build[1]:
        return None
    url, sha256 = build
    home = directory or Path(tempfile.gettempdir()) / "ocheso-stockfish" / sha256[:16]
    exe = home / "stockfish"
    with _fetch_lock:
        if exe.exists():
            return str(exe)
        home.mkdir(parents=True, exist_ok=True)
        archive = home / "download.tar.gz"
        digest = hashlib.sha256()
        with urllib.request.urlopen(url, timeout=60) as r, open(archive, "wb") as f:  # noqa: S310 - pinned https URL
            while chunk := r.read(1 << 20):
                digest.update(chunk)
                f.write(chunk)
        if digest.hexdigest() != sha256:
            archive.unlink(missing_ok=True)
            raise RuntimeError(f"Stockfish download did not match its published SHA-256 ({url})")
        unpacked = home / "unpacked"
        with tarfile.open(archive) as t:
            t.extractall(unpacked, filter="data")
        archive.unlink()
        binary = _first_that_runs(unpacked)
        if binary is None:
            shutil.rmtree(unpacked, ignore_errors=True)
            raise RuntimeError(f"No Stockfish binary in {url} runs on this machine")
        partial = home / "stockfish.partial"
        binary.replace(partial)
        partial.replace(exe)
        shutil.rmtree(unpacked, ignore_errors=True)
        return str(exe)


# The archive holds the binary (or one per instruction set) beside its sources.
# Rather than guess which this CPU runs, try them, the likeliest first.
_PREFERENCE = ("universal", "avx2", "bmi2", "sse41-popcnt", "x86-64", "armv8", "arm64")


def _first_that_runs(root: Path) -> Optional[Path]:
    files = [p for p in root.rglob("stockfish*") if p.is_file() and p.stat().st_size > 1_000_000]

    def rank(p: Path) -> int:
        name = p.name.lower()
        return next((i for i, tag in enumerate(_PREFERENCE) if tag in name), len(_PREFERENCE))

    for candidate in sorted(files, key=lambda p: (rank(p), -p.stat().st_size)):
        candidate.chmod(0o755)
        try:
            out = subprocess.run([str(candidate)], input="uci\nquit\n", capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if "uciok" in out.stdout:
            return candidate
    return None


# -----------------------------------------------------------------------------
# UCI, read the brain's way
# -----------------------------------------------------------------------------
def go_command(req: dict) -> str:
    parts = ["go"]
    if req.get("depth") is not None:
        parts += ["depth", str(req["depth"])]
    if req.get("nodes") is not None:
        parts += ["nodes", str(req["nodes"])]
    if req.get("movetimeMs") is not None:
        parts += ["movetime", str(req["movetimeMs"])]
    if len(parts) == 1:
        parts += ["depth", "12"]
    if req.get("searchMoves"):
        parts += ["searchmoves", *req["searchMoves"]]
    return " ".join(parts)


_BOUND = re.compile(r" (lowerbound|upperbound)( |$)")


def parse_info(text: str) -> Optional[dict]:
    """One `info ... pv ...` line, or None. Bound lines are interim guesses during
    a re-search and are skipped."""
    if not text.startswith("info ") or " pv " not in text or _BOUND.search(text):
        return None
    tokens = text.strip().split()
    depth, multipv, cp, mate, pv = -1, 1, None, None, []
    i = 1
    while i < len(tokens):
        t = tokens[i]
        if t == "depth":
            i += 1
            depth = int(tokens[i])
        elif t == "multipv":
            i += 1
            multipv = int(tokens[i])
        elif t == "score":
            kind, value = tokens[i + 1], int(tokens[i + 2])
            i += 2
            if kind == "cp":
                cp = value
            elif kind == "mate":
                mate = value
        elif t == "pv":
            pv = tokens[i + 1:]
            break
        i += 1
    if depth < 1 or not pv or (cp is None and mate is None):
        return None
    line = {"move": pv[0], "pv": pv}
    if cp is not None:
        line["scoreCp"] = cp
    if mate is not None:
        line["mate"] = mate
    return {"depth": depth, "multipv": multipv, "line": line}


class UciCollector:
    """Accumulates a search's output; for each depth the last exact line per MultiPV slot stands."""

    def __init__(self) -> None:
        self.by_depth: dict[int, dict[int, dict]] = {}
        self.best_move: Optional[str] = None
        self.done = False

    def push(self, text: str) -> bool:
        if text.startswith("bestmove"):
            m = re.match(r"^bestmove (\S+)", text)
            self.best_move = m.group(1) if m and m.group(1) not in ("(none)", "0000") else None
            self.done = True
            return True
        info = parse_info(text)
        if info:
            self.by_depth.setdefault(info["depth"], {})[info["multipv"]] = info["line"]
        return False

    def result(self) -> dict:
        return {
            "bestMove": self.best_move,
            "byDepth": [
                {"depth": d, "lines": [slots[k] for k in sorted(slots)]} for d, slots in sorted(self.by_depth.items())
            ],
        }


class Stockfish:
    """One Stockfish process, single-threaded, one search at a time."""

    def __init__(self, path: Optional[str] = None, hash_mb: int = 16, threads: int = 1):
        exe = path or stockfish_path()
        if not exe:
            raise RuntimeError("Stockfish not found: set STOCKFISH_PATH")
        self.proc = subprocess.Popen(
            [exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
        )
        self.lock = threading.Lock()
        self.name = ""
        self._send("uci")

        def ready(line: str) -> bool:
            if line.startswith("id name "):
                self.name = line[len("id name "):]
            return line == "uciok"

        self._until(ready)
        self._send(f"setoption name Threads value {threads}")
        self._send(f"setoption name Hash value {hash_mb}")
        self._ready()

    def _send(self, line: str) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()

    def _until(self, stop, collector: Optional[UciCollector] = None) -> None:
        assert self.proc.stdout is not None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("Stockfish exited")
            line = line.rstrip("\n")
            if collector is not None and collector.push(line):
                return
            if stop(line):
                return

    def _ready(self) -> None:
        self._send("isready")
        self._until(lambda line: line == "readyok")

    def search(self, req: dict) -> dict:
        with self.lock:
            self._send("ucinewgame")
            self._ready()
            self._send(f"setoption name MultiPV value {max(1, req.get('multiPv') or 1)}")
            self._send(f"position fen {req['fen']}")
            self._send(go_command(req))
            collector = UciCollector()
            self._until(lambda _line: False, collector)
            return collector.result()

    @property
    def matches_calibration(self) -> bool:
        return self.name.startswith(STOCKFISH_VERSION)

    def alive(self) -> bool:
        return self.proc.poll() is None

    def close(self) -> None:
        try:
            self._send("quit")
        except Exception:
            pass
        self.proc.kill()


# -----------------------------------------------------------------------------
# Maia
# -----------------------------------------------------------------------------
class Maia:
    """Maia's policy per band, through onnxruntime. Sessions load on first use."""

    def __init__(self, directory: Optional[str] = None):
        self.dir = Path(directory or os.environ.get("MAIA_DIR") or DEFAULT_MAIA_DIR)
        self.sessions: dict[int, object] = {}
        self.lock = threading.Lock()

    def available(self, band: int) -> bool:
        return (self.dir / f"maia-{band}.onnx").exists()

    def _session(self, band: int):
        with self.lock:
            if band not in self.sessions:
                import onnxruntime as ort

                opts = ort.SessionOptions()
                opts.intra_op_num_threads = 1
                opts.inter_op_num_threads = 1
                self.sessions[band] = ort.InferenceSession(str(self.dir / f"maia-{band}.onnx"), opts)
            return self.sessions[band]

    def logits(self, fens: list[str], from_standard_start: bool, band: int) -> list[float]:
        import numpy as np

        planes = np.asarray(maia_input(fens, from_standard_start), dtype=np.float32).reshape(1, MAIA_PLANES, 8, 8)
        out = self._session(band).run(["/output/policy"], {"/input/planes": planes})  # type: ignore[attr-defined]
        return out[0][0].tolist()

    def policy(self, fen: str, history: list[str], band: int) -> Optional[dict[str, float]]:
        if not self.available(band):
            return None
        if history:
            h = maia_history(None, history, fen)
            fens, standard = h["fens"], h["fromStandardStart"]
        else:
            fens, standard = [fen], False
        return maia_policy(self.logits(fens, standard, band), fen)


class Engines:
    """What `analyse_position` asks: search, and the human prior when Maia is there."""

    def __init__(self, stockfish: Stockfish, maia: Optional[Maia] = None):
        self.stockfish = stockfish
        self.maia = maia

    def search(self, req: dict) -> dict:
        return self.stockfish.search(req)

    def policy(self, fen: str, history: list[str], band: int) -> Optional[dict[str, float]]:
        return self.maia.policy(fen, history, band) if self.maia else None
