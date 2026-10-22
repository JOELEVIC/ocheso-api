"""
The engines the brain asks: Stockfish for search, Maia for "what would a person
at this rating play".

Stockfish runs as a UCI child process and is read the brain's way - every
depth, every MultiPV line, indexed by move (the same parsing as calibration's).
Maia runs through onnxruntime on the same ONNX weights calibration used, one
session per rating band, loaded on first use.

Stockfish ships with the API: agents/bin/stockfish-linux-x86-64 is the
official Stockfish 19 release for Linux x86-64 (the servers), checked against
its published SHA-256 and proven to search exactly as the engine calibration
v2 was fitted on (agents/bin/README.md). Nothing is downloaded while a request
waits. First found wins: STOCKFISH_PATH; the bundled binary, on a machine it
runs on; `stockfish` on the PATH (development on a Mac). `Stockfish.name`
says what is really running, and `health()` reports it and where it came from.

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

# The engine the priors were fitted on, and the build that ships with the API.
STOCKFISH_VERSION = "Stockfish 19"
BUNDLED_DIR = Path(__file__).parent / "bin"
BUNDLED = {("Linux", "x86_64"): BUNDLED_DIR / "stockfish-linux-x86-64"}
RELEASE = {
    "url": "https://github.com/official-stockfish/Stockfish/releases/download/sf_19/stockfish-linux-x86-64-universal.tar.gz",
    "archive_sha256": "9defc0d4e55d49c65a6d042f3e571a39fcea499ade6dbe741b53b8c65e03611f",
    "member": "stockfish/stockfish-linux-x86-64-universal",
    "binary_sha256": "0f83d24cc46d2c66c60f16001af5444873bc112b7d028594513426894c12da19",
}
_copy_lock = threading.Lock()


def stockfish_source() -> tuple[Optional[str], str]:
    """Where Stockfish is, and how it was found: configured, bundled or path."""
    configured = os.environ.get("STOCKFISH_PATH")
    if configured:
        return configured, "configured"
    bundled = BUNDLED.get((platform.system(), platform.machine()))
    if bundled is not None and bundled.exists():
        return _executable(bundled), "bundled"
    return shutil.which("stockfish"), "path"


def stockfish_path() -> Optional[str]:
    return stockfish_source()[0]


def _executable(binary: Path) -> str:
    """The bundled binary, runnable. Deploys that drop the execute bit get a copy
    in the temp directory, made once per instance from the bundle - a local copy,
    not a download. (Mode bits, not os.access: as root, on some mounts, access()
    says yes and exec still refuses; Stockfish() retries with the copy then.)"""
    if binary.stat().st_mode & 0o111:
        return str(binary)
    return _runnable_copy(binary)


def _runnable_copy(binary: Path) -> str:
    copy = Path(tempfile.gettempdir()) / "ocheso-stockfish" / binary.name
    with _copy_lock:
        if not copy.exists():
            copy.parent.mkdir(parents=True, exist_ok=True)
            partial = copy.with_suffix(".partial")
            shutil.copyfile(binary, partial)
            partial.chmod(0o755)
            partial.replace(copy)
    return str(copy)


def update_bundled(out: Path = BUNDLED["Linux", "x86_64"]) -> str:
    """For maintainers: fetch the pinned release, verify archive and binary, and
    write the bundled binary. Never called while serving.

        python -m agents.engines update-bundled
    """
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "release.tar.gz"
        digest = hashlib.sha256()
        with urllib.request.urlopen(RELEASE["url"], timeout=120) as r, open(archive, "wb") as f:  # noqa: S310 - pinned https URL
            while chunk := r.read(1 << 20):
                digest.update(chunk)
                f.write(chunk)
        if digest.hexdigest() != RELEASE["archive_sha256"]:
            raise RuntimeError("the release archive does not match its published SHA-256")
        with tarfile.open(archive) as t:
            data = t.extractfile(t.getmember(RELEASE["member"])).read()  # type: ignore[union-attr]
    if hashlib.sha256(data).hexdigest() != RELEASE["binary_sha256"]:
        raise RuntimeError("the binary in the release is not the one that was tested")
    out.parent.mkdir(parents=True, exist_ok=True)
    partial = out.with_suffix(".partial")
    partial.write_bytes(data)
    partial.chmod(0o755)
    partial.replace(out)
    return str(out)


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
        exe, self.source = (path, "given") if path else stockfish_source()
        if not exe:
            raise RuntimeError("Stockfish not found: set STOCKFISH_PATH")
        try:
            self.proc = self._spawn(exe)
        except PermissionError:
            if self.source != "bundled":
                raise
            # The deploy kept the bytes but not the right to run them.
            exe = _runnable_copy(Path(exe))
            self.proc = self._spawn(exe)
        self.path = exe
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

    @staticmethod
    def _spawn(exe: str) -> subprocess.Popen:
        return subprocess.Popen(
            [exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1
        )

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


if __name__ == "__main__":
    import sys

    if sys.argv[1:] == ["update-bundled"]:
        print(update_bundled())
    else:
        print("usage: python -m agents.engines update-bundled")
