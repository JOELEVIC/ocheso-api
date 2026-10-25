"""
Where things live on the site, as the API hands them out (spec A10, E2).

The hosted page, the embed snippets and the frame policy are written here
once, so the platform API's create response, the embed bundle and the policy
the site's proxy reads can never point at different places.
"""

from __future__ import annotations

import html
from typing import Optional
from urllib.parse import quote

from config import settings
from schemas.org import origin_ok


def hosted_url(org_slug: Optional[str], slug: str) -> str:
    """The branded page for an organisation's event; the console's page for a
    personal one."""
    if org_slug:
        return f"{settings.SITE_URL}/o/{quote(org_slug)}/{quote(slug)}"
    return f"{settings.SITE_URL}/tournaments/{quote(slug)}"


def embed_lang(language: Optional[str]) -> str:
    return "fr" if language == "fr" else "en"


def embed_snippets(org_slug: Optional[str], t: dict) -> dict:
    """{script, iframe, link} for a tournament - what Studio's Install step
    shows, ready to paste. Every value is escaped for the attribute it sits in."""
    slug, title = t["slug"], t.get("title") or t["slug"]
    link = hosted_url(org_slug, slug)
    lang = embed_lang(t.get("language"))
    e = lambda s: html.escape(s, quote=True)  # noqa: E731
    script = (
        f'<div data-ocheso-tournament="{e(slug)}" data-view="tournament" data-theme="auto" data-lang="{lang}">\n'
        f'  <a href="{e(link)}">{e(title)}</a>\n</div>\n'
        f'<script async src="{settings.SITE_URL}/embed/v1.js"></script>'
    )
    iframe = (
        f'<iframe data-ocheso-frame src="{settings.SITE_URL}/embed/{lang}/t/{e(quote(slug))}" title="{e(title)}"'
        ' style="width:100%;min-height:480px;border:0" allow="fullscreen; autoplay; clipboard-write; web-share"'
        ' referrerpolicy="origin"></iframe>'
    )
    return {"script": script, "iframe": iframe, "link": link}


def frame_ancestors(allowed_origins: Optional[list[str]]) -> str:
    """The CSP frame-ancestors value for an organisation's embeds (spec D3):
    "*" when it lists no origins, otherwise 'self' (so Studio's previews work)
    and each origin. Every entry is re-checked before it goes into a header:
    the database checked it once, but a header is the wrong place to find out
    a check was missed."""
    if not allowed_origins:
        return "*"
    # A list that fails the check shrinks to 'self' rather than opening up.
    origins = [o for o in allowed_origins if isinstance(o, str) and origin_ok(o)]
    return " ".join(["'self'", *origins])
