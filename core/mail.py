"""
Mail: invitations and organiser notices, sent through Resend.

The database decides WHAT to send and WHEN (unsent tournament_invites, and
private.mail_outbox rows from invite_org_member, the autopilot's postponements
and disabled webhooks); this module only renders and delivers. The autopilot
tick (autopilot.py) takes a batch with `sys-mail-batch` - each row held for two
minutes - turns it into messages (`from_batch`), sends them (`send_outbox`)
and reports back with `sys-mail-done` (`to_done`). A crash in between leaves
rows whose hold simply lapses, to be sent on a later tick.

Without RESEND_API_KEY and MAIL_FROM nothing is sent and nothing pretends to
be: the tick skips mail, rows stay queued, and GET /health says "mail: off".

Each message is
    {id, to, template, locale: en|fr|both, data: {...}}
and each result
    {id, ok, provider_id?, error?, permanent?}
(`permanent`: retrying will not help - a template this API does not know, a
message that cannot be rendered, an address Resend refuses). Only successes
and permanent failures are reported to the database; anything else (Resend
down, a key being rotated, a rate limit) is left for the hold to lapse.

Copy follows docs/OCHESO_PLATFORMS.md F4: plain, no hype. The invitation never
says whether the address already has an account - the organiser cannot learn
that from Ocheso, so the email cannot hint at it either.
"""

from __future__ import annotations

import hashlib
import html
import logging
import re
from datetime import timezone
from email.utils import formataddr, parseaddr
from typing import Any, Optional
from urllib.parse import quote, urlencode, urlsplit, urlunsplit, parse_qsl
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx

from config import settings
from db import ts

log = logging.getLogger("ocheso.mail")

EMAIL = re.compile(r"^[^@\s<>(),;:\"]{1,64}@[^@\s<>(),;:\"]+\.[^@\s<>(),;:\"]{2,}$")
BATCH_MAX = 100  # Resend's batch limit
# A partner page for "I'm in": an https origin and a plain path - the same
# rules as private.plain_path in db/platforms.sql, held again here so a row
# that somehow got past the database still cannot leave the partner's origin.
PARTNER_ORIGIN = re.compile(r"^https://[a-z0-9.-]+(:[0-9]{1,5})?$")
PLAIN_PATH = re.compile(r"^/[A-Za-z0-9._~!$&*+,;=:@%/-]{0,299}$")
_UNPLAIN = re.compile(r"//|(^|/)\.\.?(/|$)|%(2f|5c|2e)", re.IGNORECASE)

_DAYS = {"en": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
         "fr": ["lun.", "mar.", "mer.", "jeu.", "ven.", "sam.", "dim."]}
_MONTHS = {"en": ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
           "fr": ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."]}
_GAMES = {
    "en": {"chess": "Chess", "international": "Checkers (international)", "brazilian": "Checkers (Brazilian)"},
    "fr": {"chess": "Échecs", "international": "Dames internationales", "brazilian": "Dames brésiliennes"},
}
_FORMATS = {
    "en": {"swiss": "Swiss", "round_robin": "Round robin", "knockout": "Knockout", "arena": "Arena"},
    "fr": {"swiss": "Système suisse", "round_robin": "Toutes rondes", "knockout": "Élimination directe",
           "arena": "Arène"},
}

COPY = {
    "en": {
        "subject": "You're invited: {title}, {when}",
        "heading": "You're invited to {title}",
        "lead": "{org} invited you to play in {title}.",
        "what": "What",
        "when": "When",
        "note": "A note from {org}",
        "button": "I'm in, open the tournament",
        "signin": "Sign in with this address ({masked}). You'll get a 6-digit code, no password.",
        "footer": "You're receiving this because {org} added this address to {title}. If it wasn't meant for "
                  "you, ignore this email: nothing happens unless you sign in.",
        "link": "Or open this link: {url}",
    },
    "fr": {
        "subject": "Invitation : {title}, {when}",
        "heading": "Vous êtes invité(e) à {title}",
        "lead": "{org} vous invite à jouer dans {title}.",
        "what": "Quoi",
        "when": "Quand",
        "note": "Un mot de {org}",
        "button": "J'y vais, ouvrir le tournoi",
        "signin": "Connectez-vous avec cette adresse ({masked}). Vous recevrez un code à 6 chiffres, "
                  "sans mot de passe.",
        "footer": "Vous recevez ce message parce que {org} a ajouté cette adresse à {title}. Si ce n'est pas "
                  "vous, ignorez-le : rien ne se passe tant que vous ne vous connectez pas.",
        "link": "Ou ouvrez ce lien : {url}",
    },
}


class Unrenderable(ValueError):
    pass


# -----------------------------------------------------------------------------
# Small pieces
# -----------------------------------------------------------------------------
def mask(email: str) -> str:
    """am•••@gmail.com - enough for the owner to recognise, not enough to copy."""
    local, _, domain = (email or "").partition("@")
    if not domain:
        return "•••"
    keep = local[:2] if len(local) > 2 else local[:1]
    return f"{keep}•••@{domain}"


def when(starts_at: Any, tz: Optional[str], locale: str) -> str:
    """'Fri 31 Oct, 19:00' / 'ven. 31 oct., 19:00' in the organiser's timezone."""
    at = ts(starts_at)
    if at is None:
        return ""
    zone = ""
    try:
        at = at.astimezone(ZoneInfo(tz)) if tz else at.astimezone(timezone.utc)
    except (ZoneInfoNotFoundError, ValueError):
        at, tz = at.astimezone(timezone.utc), None
    if not tz:
        zone = " UTC"  # a personal event has no organisation, so no timezone of its own
    lang = "fr" if locale == "fr" else "en"
    return f"{_DAYS[lang][at.weekday()]} {at.day} {_MONTHS[lang][at.month - 1]}, {at:%H:%M}{zone}"


def what(data: dict, locale: str) -> str:
    lang = "fr" if locale == "fr" else "en"
    game = (data.get("variant") or "international") if data.get("game") == "checkers" else "chess"
    parts = [_GAMES[lang].get(game, ""), _FORMATS[lang].get(data.get("format") or "", "")]
    base, inc = data.get("clock_base_s"), data.get("clock_increment_s")
    if base:
        base = int(base)
        parts.append(f"{base // 60 if base % 60 == 0 else str(base) + 's'}+{int(inc or 0)}")
    return " · ".join(p for p in parts if p)


def _with_param(url: str, key: str, value: str) -> str:
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != key] + [(key, value)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def partner_page(install: Optional[dict]) -> Optional[str]:
    """origin + path of an install sys-mail-batch chose, or None. The
    database hands one over only for an origin on the organisation's own
    allowed list; this refuses anything that is not an https origin with a
    plain path, and a bare origin too - the partner's home page has no embed
    to take the invitation, so the hosted page is the better link."""
    install = install or {}
    origin, path = (install.get("origin") or "").rstrip("/"), install.get("path") or ""
    if not PARTNER_ORIGIN.fullmatch(origin) or not PLAIN_PATH.fullmatch(path) or _UNPLAIN.search(path):
        return None
    return origin + path


def invite_url(data: dict) -> str:
    """Where "I'm in" goes (spec F4): the partner's own page when the embed
    was seen installed there - on an origin the organiser listed, see
    partner_page - else the branded hosted page, else - for a personal
    tournament - the console's invite page. On the partner's page the link
    names the event too (ocheso_t), so the loader hands the invitation to that
    event's widget: the page seen last may carry others."""
    token, slug = data["token"], data["slug"]
    partner = data.get("partner_url")
    if partner and re.fullmatch(r"https://[^\s\"'<>()]+", partner):
        return _with_param(_with_param(partner, "ocheso_invite", token), "ocheso_t", slug)
    org = (data.get("org") or {}).get("slug")
    if org:
        return f"{settings.SITE_URL}/o/{quote(org)}/{quote(slug)}?invite={token}"
    return f"{settings.SITE_URL}/invite/{quote(slug)}?e={token}"


def sender(org_name: Optional[str]) -> str:
    """"Yoursite via Ocheso" <the configured address>. The display name is
    cleaned of anything that could break out of the header."""
    configured_name, address = parseaddr(settings.MAIL_FROM)
    if not org_name:
        return formataddr((configured_name or "Ocheso", address))
    clean = re.sub(r"[\r\n\"<>,;:\\]", "", org_name).strip()[:60] or "Ocheso"
    return formataddr((f"{clean} via Ocheso", address))


def _esc(text: Any) -> str:
    return html.escape(str(text or ""), quote=True)


def _note_html(note: str) -> str:
    return "<br>".join(_esc(line) for line in note.strip().splitlines())


# -----------------------------------------------------------------------------
# Templates
# -----------------------------------------------------------------------------
def _invite_block(lang: str, data: dict, to: str, url: str) -> tuple[str, str]:
    c = COPY[lang]
    org = (data.get("org") or {}).get("name") or data.get("inviter_name") or "An organiser"
    title = data.get("title") or ""
    w = when(data.get("starts_at"), data.get("timezone"), lang)
    note = (data.get("note") or "").strip()
    rows_html = (
        f'<p style="margin:0 0 4px;color:#6b7280;font-size:13px">{_esc(c["what"])}</p>'
        f'<p style="margin:0 0 12px">{_esc(what(data, lang))}</p>'
        f'<p style="margin:0 0 4px;color:#6b7280;font-size:13px">{_esc(c["when"])}</p>'
        f'<p style="margin:0 0 16px">{_esc(w)}{" (" + _esc(data.get("timezone")) + ")" if data.get("timezone") else ""}</p>'
    )
    note_html = (
        f'<p style="margin:0 0 4px;color:#6b7280;font-size:13px">{_esc(c["note"].format(org=org))}</p>'
        f'<blockquote style="margin:0 0 16px;padding:8px 12px;border-left:3px solid #e5e7eb">{_note_html(note)}</blockquote>'
        if note else ""
    )
    block = (
        f'<h1 style="font-size:20px;margin:0 0 12px">{_esc(c["heading"].format(title=title))}</h1>'
        f'<p style="margin:0 0 16px">{_esc(c["lead"].format(org=org, title=title))}</p>'
        f"{rows_html}{note_html}"
        f'<p style="margin:0 0 16px"><a href="{_esc(url)}" style="display:inline-block;background:#2f55e0;'
        f'color:#fff;text-decoration:none;padding:12px 18px;border-radius:10px;font-weight:600">'
        f'{_esc(c["button"])}</a></p>'
        f'<p style="margin:0 0 8px;font-size:14px">{_esc(c["signin"].format(masked=mask(to)))}</p>'
        f'<p style="margin:0 0 16px;font-size:12px;color:#6b7280;word-break:break-all">'
        f'{_esc(c["link"].format(url=url))}</p>'
        f'<p style="margin:0;font-size:12px;color:#6b7280">{_esc(c["footer"].format(org=org, title=title))}</p>'
    )
    text = "\n\n".join(p for p in [
        c["heading"].format(title=title),
        c["lead"].format(org=org, title=title),
        f'{c["what"]}: {what(data, lang)}',
        f'{c["when"]}: {w}' + (f' ({data["timezone"]})' if data.get("timezone") else ""),
        f'{c["note"].format(org=org)}:\n{note}' if note else "",
        f'{c["button"]}: {url}',
        c["signin"].format(masked=mask(to)),
        c["footer"].format(org=org, title=title),
    ] if p)
    return block, text


def render_invite(to: str, locale: str, data: dict) -> dict:
    """An invitation to a tournament, in its language; "both" sends one email
    with English first and French second."""
    for need in ("token", "slug", "title"):
        if not data.get(need):
            raise Unrenderable(f"invite without {need}")
    url = invite_url(data)
    langs = ["en", "fr"] if locale == "both" else ["fr" if locale == "fr" else "en"]
    blocks = [_invite_block(lang, data, to, url) for lang in langs]
    subjects = [COPY[lang]["subject"].format(title=data["title"], when=when(data.get("starts_at"), data.get("timezone"), lang))
                for lang in langs]
    html_body = '<hr style="border:0;border-top:1px solid #e5e7eb;margin:24px 0">'.join(b for b, _ in blocks)
    return {
        "subject": " / ".join(subjects)[:200],
        "html": _page(html_body, "fr" if langs == ["fr"] else "en"),
        "text": "\n\n---\n\n".join(t for _, t in blocks),
        "org": (data.get("org") or {}).get("name"),
        "reply_to": (data.get("org") or {}).get("support_email"),
    }


def _notice(subject: str, lines: list[str], link: Optional[tuple[str, str]] = None, org: Optional[str] = None,
            reply_to: Optional[str] = None) -> dict:
    body = "".join(f'<p style="margin:0 0 12px">{_esc(line)}</p>' for line in lines)
    if link:
        body += (f'<p style="margin:0 0 12px"><a href="{_esc(link[1])}" style="color:#2f55e0">{_esc(link[0])}</a></p>')
    text = "\n\n".join(lines + ([f"{link[0]}: {link[1]}"] if link else []))
    return {"subject": subject[:200], "html": _page(body, "en"), "text": text, "org": org, "reply_to": reply_to}


def render(message: dict) -> dict:
    """{subject, html, text, org, reply_to} for one outbox message."""
    template, data = message.get("template"), message.get("data") or {}
    to, locale = message.get("to") or "", message.get("locale") or "en"
    org = data.get("org") or {}
    if template == "invite":
        return render_invite(to, locale, data)
    if template == "org_invite":
        # Joining a team takes a yes (db/platforms.sql claim_invites): the link
        # is the invitation page, which shows the team and accepts it with
        # the token, rather than Studio, which signing in alone never joins.
        name = org.get("name") or "an organisation"
        if not data.get("token"):
            raise Unrenderable("org invite without token")
        link = f"{settings.SITE_URL}/invite/{quote(org.get('slug') or 'team')}?e={quote(data['token'])}"
        return _notice(
            f"Join {name} on Ocheso",
            [f"{data.get('inviter_name') or 'An admin'} invited you to {name}'s team on Ocheso as {data.get('role') or 'staff'}.",
             f"Open the invitation and accept it with this address ({mask(to)}). You'll get a 6-digit code, no password. "
             "If you don't, nothing happens."],
            ("Open the invitation", link), org.get("name"), org.get("support_email"),
        )
    if template == "postponed":
        have = (f" ({data['approved']} of {data['min_players']} players)"
                if data.get("approved") is not None and data.get("min_players") else "")
        return _notice(
            f"{data.get('title') or 'Your tournament'} was postponed",
            [data.get("note") or f"Not enough players had entered at the start time{have}, so the autopilot postponed it.",
             f"New start: {when(data.get('starts_at'), data.get('timezone') or org.get('timezone'), 'en')}."],
            ("Open the tournament", f"{settings.SITE_URL}/tournaments/{quote(data.get('slug') or '')}/manage"),
            org.get("name"),
        )
    if template == "stalled":
        return _notice(
            f"Autopilot needs a hand: {data.get('title') or 'your tournament'}",
            [f"The autopilot can't continue: {data.get('reason') or 'see the tournament page'}.",
             "It will try again in five minutes. You can also pair or start the round yourself."],
            ("Open the tournament", f"{settings.SITE_URL}/tournaments/{quote(data.get('slug') or '')}/manage"),
            org.get("name"),
        )
    if template == "webhook_disabled":
        return _notice(
            "A webhook endpoint was switched off",
            [f"Deliveries to {data.get('url') or 'your endpoint'} kept failing, so it has been disabled.",
             f"Reason: {data.get('reason') or 'repeated failures'}. Fix the endpoint, then switch it back on in Studio."],
            ("Open Developers", f"{settings.SITE_URL}/studio/{quote(org.get('slug') or '')}/developers"),
            org.get("name"),
        )
    raise Unrenderable(f"unknown template {template!r}")


def _page(body: str, lang: str) -> str:
    return (
        f'<!doctype html><html lang="{lang}"><body style="margin:0;padding:24px;background:#f5f7fa">'
        f'<div style="max-width:560px;margin:0 auto;background:#fff;border-radius:12px;padding:24px;'
        f'font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0e0f12;line-height:1.5">'
        f"{body}</div></body></html>"
    )


# -----------------------------------------------------------------------------
# The database's batch, in and out
# -----------------------------------------------------------------------------
def _invite_message(i: dict) -> dict:
    """A tournament_invites row as sys-mail-batch hands it over."""
    t = i.get("tournament") or {}
    org = i.get("org") or None
    partner = partner_page(i.get("install"))
    clock = t.get("clock") or {}
    return {
        "id": f"invite:{i['id']}",
        # Which send of this invite it is (resend_invite and re-adding count
        # up), so the idempotency key is new for a new send - see _post_batch.
        "attempt": int(i.get("resends") or 0),
        "to": i.get("to"),
        "template": "invite",
        "locale": i.get("language") or "en",
        "data": {
            "token": i.get("token"), "slug": t.get("slug"), "title": t.get("title"), "starts_at": t.get("starts_at"),
            "timezone": (org or {}).get("timezone"), "game": t.get("game"), "variant": t.get("variant"),
            "format": t.get("format"), "clock_base_s": clock.get("base_s"), "clock_increment_s": clock.get("inc_s"),
            "org": org, "note": i.get("note"), "partner_url": partner, "inviter_name": i.get("invited_by"),
        },
    }


def _outbox_message(m: dict) -> dict:
    """A private.mail_outbox row: kind 'org-invite' | 'postponed' |
    'webhook-disabled' -> the template of the same name."""
    data = dict(m.get("data") or {})
    if m.get("org") and not data.get("org"):
        data["org"] = m["org"]
    elif m.get("org"):
        data["org"] = {**m["org"], **data["org"]}
    if data.get("invited_by") and not data.get("inviter_name"):
        data["inviter_name"] = data["invited_by"]
    return {"id": f"outbox:{m['id']}", "to": m.get("to"), "template": (m.get("kind") or "").replace("-", "_"),
            "locale": "en", "data": data}


def from_batch(batch: dict) -> list[dict]:
    """sys-mail-batch's {invites, outbox} as messages for send_outbox."""
    if isinstance(batch, list):  # already messages
        return batch
    return [_invite_message(i) for i in batch.get("invites") or []] + \
        [_outbox_message(m) for m in batch.get("outbox") or []]


def to_done(results: list[dict]) -> dict:
    """send_outbox's results as sys-mail-done {invites, outbox}: successes and
    permanent failures only."""
    out: dict[str, list] = {"invites": [], "outbox": []}
    for r in results:
        if not (r.get("ok") or r.get("permanent")):
            continue
        kind, _, raw = str(r["id"]).partition(":")
        entry = {"id": int(raw) if kind == "outbox" and raw.isdigit() else raw, "ok": bool(r.get("ok"))}
        if r.get("error"):
            entry["error"] = r["error"]
        if kind in ("invite", "outbox"):
            out["invites" if kind == "invite" else "outbox"].append(entry)
    return out


# -----------------------------------------------------------------------------
# Delivery
# -----------------------------------------------------------------------------
def send_outbox(batch: list[dict], client: Optional[httpx.Client] = None) -> list[dict]:
    """Render and send a batch from the outbox; one result per message."""
    results: dict[Any, dict] = {}
    ready: list[tuple[dict, dict]] = []
    for m in batch:
        to = (m.get("to") or "").strip()
        if not EMAIL.fullmatch(to) or len(to) > 254:
            results[m["id"]] = {"id": m["id"], "ok": False, "error": "invalid address", "permanent": True}
            continue
        try:
            r = render(m)
        except (Unrenderable, KeyError, TypeError, ValueError) as e:
            results[m["id"]] = {"id": m["id"], "ok": False, "error": f"render: {e}", "permanent": True}
            continue
        email = {"from": sender(r.get("org")), "to": [to], "subject": r["subject"], "html": r["html"], "text": r["text"]}
        if r.get("reply_to") and EMAIL.fullmatch(r["reply_to"]):
            email["reply_to"] = r["reply_to"]
        ready.append((m, email))
    for i in range(0, len(ready), BATCH_MAX):
        chunk = ready[i:i + BATCH_MAX]
        for res in _post_batch(chunk, client):
            results[res["id"]] = res
    return [results[m["id"]] for m in batch if m["id"] in results]


def idempotency_key(messages: list[dict]) -> str:
    """Resend keeps idempotency keys for 24 h: the same SEND of the same rows
    twice (a tick that died after sending, before sys-mail-done) is delivered
    once. Each message's `attempt` is in it - an invite's resend count - so a
    resend, or the address added again, is a new send with a new key; with
    the row id alone Resend would answer the cached success and deliver
    nothing, and the invite would be marked sent all the same."""
    parts = sorted(f"{m['id']}#{int(m.get('attempt') or 0)}" for m in messages)
    return hashlib.sha256(",".join(parts).encode()).hexdigest()


def _post_batch(chunk: list[tuple[dict, dict]], client: Optional[httpx.Client]) -> list[dict]:
    ids = [m["id"] for m, _ in chunk]
    key = idempotency_key([m for m, _ in chunk])
    headers = {
        "Authorization": f"Bearer {settings.RESEND_API_KEY}",
        "Content-Type": "application/json",
        "Idempotency-Key": f"ocheso-mail-{key}",
        # One bad address refuses only itself, not the whole batch.
        "x-batch-validation": "permissive",
    }
    own = client is None
    http = client or httpx.Client(timeout=15.0)
    try:
        resp = http.post(f"{settings.RESEND_API_URL}/emails/batch", headers=headers, json=[e for _, e in chunk])
    except httpx.HTTPError as e:
        return [{"id": i, "ok": False, "error": f"network: {type(e).__name__}"} for i in ids]
    finally:
        if own:
            http.close()
    if resp.status_code >= 300:
        # 400/422: Resend refused what was sent, and would again. 401/403
        # are this API's configuration (a key being rotated), 429 and 5xx are
        # Resend's: none of those is the invitation's fault, so it goes again.
        # 409 is two things. invalid_idempotent_request: this key already
        # went out with other content (the event moved between a send and
        # its report) - the same key can never succeed, so it is permanent
        # and the organiser sees it and can send it again, as a new send.
        # concurrent_idempotent_requests: the same send is in flight; later.
        permanent = resp.status_code in (400, 422)
        error = f"resend {resp.status_code}"
        if resp.status_code == 409:
            try:
                name = (resp.json() or {}).get("name")
            except (ValueError, AttributeError):
                name = None
            if name == "invalid_idempotent_request":
                permanent, error = True, "resend 409: already sent with different content; send it again"
        return [{"id": i, "ok": False, "error": error, "permanent": permanent} for i in ids]
    try:
        body = resp.json()
    except ValueError:
        body = {}
    failed = {e.get("index"): e.get("message") or "refused" for e in (body.get("errors") or []) if isinstance(e, dict)}
    sent = iter(body.get("data") or [])
    out = []
    for n, i in enumerate(ids):
        if n in failed:
            out.append({"id": i, "ok": False, "error": str(failed[n])[:200], "permanent": True})
        else:
            got = next(sent, None) or {}
            out.append({"id": i, "ok": True, "provider_id": got.get("id")})
    return out
