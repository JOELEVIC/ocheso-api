"""
The API is two Vercel functions on one domain (vercel.json): core/main.py, light,
and agents_main.py, which alone carries Stockfish, Maia and numpy. These
hold the split: every route is served by exactly one of them, vercel.json sends
each path to the function that has it, and the light one never imports what
only agents need.
"""

import functools
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_ENV = {"SUPABASE_URL": "https://x.supabase.co", "SUPABASE_ANON_KEY": "sb_publishable_x", "PATH": "/usr/bin:/bin"}


@functools.lru_cache(maxsize=None)
def _served(module: str) -> frozenset[str]:
    """Every documented path an app serves, read from its OpenAPI schema in a
    fresh interpreter. Fresh, because dev.py adds the agents' routers to the
    core app object itself, so in one process "core" would include them; and
    OpenAPI, because newer FastAPI keeps included routers as lazy entries in
    app.routes, where a scan for `.path` quietly finds nothing at all - which
    made these checks pass while checking no route."""
    code = ("import sys, json; sys.path[:0] = [sys.argv[1], sys.argv[2]]; "
            f"from {module} import app; print(json.dumps(sorted(app.openapi()['paths'])))")
    out = subprocess.run([sys.executable, "-c", code, str(ROOT / "core"), str(ROOT)], capture_output=True,
                         text=True, env=_ENV, cwd=ROOT / "tests")
    assert out.returncode == 0, out.stderr
    return frozenset(json.loads(out.stdout.strip().splitlines()[-1]))


def _paths(app) -> set[str]:
    return set(app.openapi()["paths"])


def test_every_route_is_served_by_exactly_one_function():
    core, agents, whole = _served("main"), _served("agents_main"), _served("dev")
    assert core and agents, "an empty set would make every check below pass"
    assert not core & agents
    assert core | agents == whole
    assert all(re.match(r"^/v1/(agents|agent-keys|connect)(/|$)", p) for p in agents)
    assert not any(re.match(r"^/v1/(agents|agent-keys|connect)(/|$)", p) for p in core)


def test_vercel_routes_each_path_to_the_function_that_has_it():
    config = json.loads((ROOT / "vercel.json").read_text())
    rules = [(re.compile("^" + r["source"].replace("(.*)", "(.*)") + "$"), r["destination"]["service"])
             for r in config["rewrites"]]

    def service_for(path: str) -> str:
        return next(svc for rx, svc in rules if rx.match(path))

    for path in _served("agents_main"):
        assert service_for(re.sub(r"\{[^}]+\}", "x", path)) == "agents", path
    for path in _served("main") | {"/", "/health", "/docs", "/openapi.json"}:
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


def test_ocheso_for_platforms_lives_in_core():
    # All new routes in the light function (docs/OCHESO_PLATFORMS.md D): a
    # tick, an embed bundle or a player token never waits for Stockfish.
    core = _served("main")
    for needed in ("/v1/orgs", "/v1/orgs/bootstrap", "/v1/orgs/{org}/keys", "/v1/platform/player-tokens",
                   "/v1/platform/tournaments/{slug}/players", "/v1/embed/t/{slug}", "/v1/embed/sessions",
                   "/v1/embed/games/{game_id}/move", "/v1/embed/ping", "/v1/embed/policy", "/v1/internal/tick",
                   "/v1/tournaments/{slug}/invites", "/v1/invites/by-token/{token}", "/v1/tournaments/{slug}/autopilot",
                   "/v1/me/embed-sessions"):
        assert needed in core, needed


def test_core_may_run_for_a_minute():
    # The tick works for up to 40 s (core/autopilot.py BUDGET_S) and must
    # still release and answer: Vercel's default would cut it off first.
    config = json.loads((ROOT / "vercel.json").read_text())
    assert config["services"]["core"]["functions"]["main.py"]["maxDuration"] == 60
    from autopilot import BUDGET_S

    assert BUDGET_S <= 45
