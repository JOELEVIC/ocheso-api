"""
Which Stockfish the agents run, and that it is the one that was tested.

The bundled binary (agents/bin) is what every deploy carries; these hold it to
the SHA-256 recorded when it was proven to search exactly as calibration's
engine did, and check the order engines are found in - without needing Linux.
"""

import hashlib
import stat
from pathlib import Path

import pytest

from agents import engines
from agents.engines import RELEASE, go_command, parse_info, stockfish_source


def test_the_bundled_binary_is_the_tested_one():
    binary = engines.BUNDLED["Linux", "x86_64"]
    assert binary.exists(), "agents/bin/stockfish-linux-x86-64 is missing - every deploy needs it"
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == RELEASE["binary_sha256"]
    assert binary.stat().st_mode & stat.S_IXUSR, "the bundled binary lost its execute bit in git"


def _fake(monkeypatch, tmp_path: Path, mode: int) -> Path:
    fake = tmp_path / "stockfish-linux-x86-64"
    fake.write_bytes(b"#!/bin/sh\n")
    fake.chmod(mode)
    monkeypatch.delenv("STOCKFISH_PATH", raising=False)
    monkeypatch.setattr(engines.platform, "system", lambda: "Linux")
    monkeypatch.setattr(engines.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(engines, "BUNDLED", {("Linux", "x86_64"): fake})
    monkeypatch.setattr(engines.tempfile, "gettempdir", lambda: str(tmp_path / "tmp"))
    return fake


def test_configured_path_wins(monkeypatch, tmp_path):
    _fake(monkeypatch, tmp_path, 0o755)
    monkeypatch.setenv("STOCKFISH_PATH", "/opt/sf")
    assert stockfish_source() == ("/opt/sf", "configured")


def test_servers_use_the_bundled_binary(monkeypatch, tmp_path):
    fake = _fake(monkeypatch, tmp_path, 0o755)
    assert stockfish_source() == (str(fake), "bundled")


def test_a_deploy_that_drops_the_execute_bit_gets_a_local_copy(monkeypatch, tmp_path):
    fake = _fake(monkeypatch, tmp_path, 0o644)
    path, source = stockfish_source()
    assert source == "bundled" and path != str(fake)
    copy = Path(path)
    assert copy.read_bytes() == fake.read_bytes() and copy.stat().st_mode & stat.S_IXUSR


def test_elsewhere_the_path_is_used(monkeypatch, tmp_path):
    _fake(monkeypatch, tmp_path, 0o755)
    monkeypatch.setattr(engines.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(engines.shutil, "which", lambda name: "/opt/homebrew/bin/stockfish")
    assert stockfish_source() == ("/opt/homebrew/bin/stockfish", "path")


def test_uci_is_read_the_brains_way():
    assert go_command({"depth": 12, "searchMoves": ["e2e4", "d2d4"]}) == "go depth 12 searchmoves e2e4 d2d4"
    assert go_command({}) == "go depth 12"
    line = parse_info("info depth 8 seldepth 10 multipv 2 score cp -35 nodes 1000 nps 1 time 3 pv e7e5 g1f3")
    assert line == {"depth": 8, "multipv": 2, "line": {"move": "e7e5", "pv": ["e7e5", "g1f3"], "scoreCp": -35}}
    assert parse_info("info depth 8 multipv 1 score cp 20 lowerbound nodes 5 pv e2e4") is None
    assert parse_info("info depth 3 multipv 1 score mate 2 pv h5f7")["line"]["mate"] == 2


@pytest.mark.skipif(not engines.shutil.which("stockfish"), reason="no Stockfish here")
def test_the_local_engine_is_the_calibrated_version():
    sf = engines.Stockfish(path=engines.shutil.which("stockfish"))
    try:
        assert sf.matches_calibration, sf.name
    finally:
        sf.close()
