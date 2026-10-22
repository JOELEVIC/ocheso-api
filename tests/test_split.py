"""
The API is two Vercel functions on one domain (vercel.json): core/main.py, light,
and agents_main.py, which alone carries Stockfish, Maia and numpy. These
hold the split: every route is served by exactly one of them, vercel.json sends
each path to the function that has it, and the light one never imports what
only agents need.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _paths(app) -> set[str]:
    return {r.path for r in app.routes if getattr(r, "include_in_schema", False)}


def test_every_route_is_served_by_exactly_one_function():
    from agents_main import app as agents_app
    from dev import app as whole
    from main import app as core_app

    core, agents = _paths(core_app), _paths(agents_app)
    assert not core & agents
    assert core | agents == _paths(whole)
    assert all(re.match(r"^/v1/(agents|agent-keys|connect)(/|$)", p) for p in agents)
    assert not any(re.match(r"^/v1/(agents|agent-keys|connect)(/|$)", p) for p in core)


def test_vercel_routes_each_path_to_the_function_that_has_it():
    from agents_main import app as agents_app
    from main import app as core_app

    config = json.loads((ROOT / "vercel.json").read_text())
    rules = [(re.compile("^" + r["source"].replace("(.*)", "(.*)") + "$"), r["destination"]["service"])
             for r in config["rewrites"]]

    def service_for(path: str) -> str:
        return next(svc for rx, svc in rules if rx.match(path))

    for path in _paths(agents_app):
        assert service_for(re.sub(r"\{[^}]+\}", "x", path)) == "agents", path
    for path in _paths(core_app) | {"/", "/health", "/docs", "/openapi.json"}:
        assert service_for(re.sub(r"\{[^}]+\}", "x", path)) == "core", path
    assert config["services"]["core"]["root"] == "core/"
    excluded = config["services"]["agents"]["functions"]["agents_main.py"]["excludeFiles"]
    for heavy_only_in_tests in ("agents/golden/**", "agents/data/calibration/**", "agents/models/maia/**", "tests/**",
                                "core/.vercel/**"):
        assert heavy_only_in_tests in excluded


def test_the_light_function_loads_nothing_heavy():
    # A fresh interpreter, as on a cold start: import the light app and look.
    code = (
        "import sys; sys.path[:0] = [sys.argv[1]]; import main; "
        "heavy = sorted(m for m in sys.modules if m.split('.')[0] in ('numpy', 'onnxruntime', 'agents', 'agent_routes')); "
        "print(','.join(heavy))"
    )
    out = subprocess.run([sys.executable, "-c", code, str(ROOT / "core")], capture_output=True, text=True,
                         env={"SUPABASE_URL": "https://x.supabase.co", "SUPABASE_ANON_KEY": "sb_publishable_x",
                              "PATH": "/usr/bin:/bin"}, cwd=ROOT / "core")
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == ""


def test_each_function_lists_only_what_it_imports():
    def names(path: Path) -> set[str]:
        return {re.split(r"[<>=\[]", line.strip())[0].lower() for line in path.read_text().splitlines()
                if line.strip() and not line.startswith(("#", "-r"))}

    core, agents = names(ROOT / "core/requirements.txt"), names(ROOT / "requirements.txt")
    assert not {"numpy", "onnxruntime", "supabase", "pytest", "uvicorn"} & core
    assert {"numpy", "chess", "postgrest"} <= agents
    # No inference runtime: under Vercel's 225 MB the function ships whole,
    # nothing installed at cold start.
    assert not {"onnxruntime", "networkx", "supabase", "pytest", "uvicorn"} & agents
    # The light code never imports anything the light function would be missing.
    for f in (ROOT / "core").rglob("*.py"):
        assert not re.search(r"^\s*(import|from) (numpy|onnxruntime|agents)\b", f.read_text(), re.M), f
