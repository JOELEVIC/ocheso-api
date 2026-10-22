"""
The chess persona: persona v2 with chess's half under `play` - strength by
phase of the game, how far it sees, how alert it is, how it checks its moves,
its style and its openings. Ratings run 100-2600, the range calibration v1 was
fitted on.
"""

from __future__ import annotations

from typing import Any

from agents.persona import COMMON_TRAITS, array, number, obj, persona_schema, string, unit

CHESS_RATING_RANGE = (100, 2600)

_offset = number(-400, 400, 0, integer=True)

REPERTOIRE_LINE = obj(
    {
        "moves": string(
            pattern=r"^([a-h][1-8][a-h][1-8][qrbn]?)( [a-h][1-8][a-h][1-8][qrbn]?)*$",
            why="UCI moves separated by spaces",
        ),
        "weight": number(0, 100, 1),
    }
)

STRENGTH = obj(
    {
        "opening": _offset,
        "middlegame": _offset,
        "endgame": _offset,
        "vision": unit(),
        "attention": unit(),
        "blunderCheck": unit(),
    },
    prefault={},
)

STYLE = obj(
    {
        k: unit()
        for k in (
            "aggression",
            "materialism",
            "riskWhenAhead",
            "riskWhenBehind",
            "simplifyWhenAhead",
            "complication",
            "kingSafety",
            "pawnStorm",
            "bishops",
            "hopeChess",
        )
    },
    prefault={},
)

OPENINGS = obj(
    {
        "white": array(REPERTOIRE_LINE, [], max_len=40),
        "blackVsE4": array(REPERTOIRE_LINE, [], max_len=40),
        "blackVsD4": array(REPERTOIRE_LINE, [], max_len=40),
        "blackVsOther": array(REPERTOIRE_LINE, [], max_len=40),
        "bookDepth": number(0, 20, 6, integer=True),
        "misremember": unit(0.1),
    },
    prefault={},
)

CHESS_PLAY = obj({"strength": STRENGTH, "style": STYLE, "openings": OPENINGS}, prefault={})

_SCHEMA = persona_schema("chess", CHESS_PLAY, CHESS_RATING_RANGE)


def persona(data: dict[str, Any]) -> dict:
    """A full persona from a partial one: every missing trait at its default.
    Raises PersonaError naming the field when something is out of range or unknown."""
    return _SCHEMA(data, "")


CHESS_TRAITS: dict[str, dict] = {
    "play.strength.opening": {"label": "Opening", "low": "plays the opening below its rating", "high": "plays the opening above its rating"},
    "play.strength.middlegame": {"label": "Middlegame", "low": "below its rating in the middlegame", "high": "above its rating in the middlegame"},
    "play.strength.endgame": {"label": "Endgame", "low": "below its rating in endgames", "high": "above its rating in endgames"},
    "play.strength.vision": {"label": "Vision", "low": "sees only the next move or two", "high": "calculates further than most at this rating"},
    "play.strength.attention": {"label": "Attention", "low": "often overlooks a piece or a threat", "high": "rarely misses what's on the board"},
    "play.strength.blunderCheck": {"label": "Blunder check", "low": "plays the first idea", "high": "looks once more before moving"},
    "play.style.aggression": {"label": "Aggression", "low": "quiet, positional", "high": "goes for the king, sacrifices"},
    "play.style.materialism": {"label": "Materialism", "low": "gives material for play", "high": "grabs every pawn"},
    "play.style.riskWhenAhead": {"label": "Risk when ahead", "low": "consolidates", "high": "keeps attacking"},
    "play.style.riskWhenBehind": {"label": "Risk when behind", "low": "defends quietly", "high": "throws everything forward"},
    "play.style.simplifyWhenAhead": {"label": "Simplifies when ahead", "low": "keeps pieces on", "high": "trades down to win"},
    "play.style.complication": {"label": "Complications", "low": "prefers clear positions", "high": "likes chaos"},
    "play.style.kingSafety": {"label": "King safety", "low": "leaves the king in the centre", "high": "castles early, keeps the shelter"},
    "play.style.pawnStorm": {"label": "Pawn storms", "low": "keeps pawns home", "high": "throws pawns at the king"},
    "play.style.bishops": {"label": "Minor pieces", "low": "prefers knights", "high": "prefers bishops"},
    "play.style.hopeChess": {"label": "Hope chess", "low": "only plays sound threats", "high": "sets traps and hopes"},
    "play.openings.misremember": {"label": "Misremembers lines", "low": "knows its book", "high": "often mixes up move orders"},
}

TRAITS: dict[str, dict] = {**COMMON_TRAITS, **CHESS_TRAITS}
