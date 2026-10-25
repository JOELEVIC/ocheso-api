# Ocheso API & Supabase Backend

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Supabase](https://img.shields.io/badge/Supabase-Backend-3ECF8E?style=flat&logo=supabase&logoColor=white)](https://supabase.com/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)

Production-ready FastAPI backend for the Ocheso tournament console and user flows, integrated with Supabase.

- **Production API URL**: `https://api.ocheso.com`
- **Interactive Swagger Docs**: `https://api.ocheso.com/docs`
- **Interactive ReDoc**: `https://api.ocheso.com/redoc`

---

## Table of Contents
1. [UI Integration Guide (Supabase & Google Auth)](#ui-integration-guide)
2. [API Endpoint Reference](#api-endpoint-reference)
3. [Local Development & Testing](#local-development--testing)
4. [Deployment & Git](#deployment--git)
5. [Changelog](#5-changelog)

---

## 1. UI Integration Guide

Since the UI uses Supabase directly for authentication (including **Google Sign-In/Sign-Up**) and real-time state synchronization, follow these guidelines to wire your frontend.

### Supabase Client Setup
```javascript
import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://ofjnhbkdqipqheyzdvym.supabase.co';
const SUPABASE_ANON_KEY = 'YOUR_SUPABASE_ANON_KEY';

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: true, autoRefreshToken: true }
});
```

### Google Sign-In / Sign-Up
```javascript
export async function signInWithGoogle() {
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: 'google',
    options: { redirectTo: window.location.origin }
  });
  if (error) console.error('Google Auth Error:', error.message);
}
```

### Making Authenticated Requests to `api.ocheso.com`
```javascript
const API_BASE = 'https://api.ocheso.com';

async function ochesoApi(endpoint, options = {}) {
  // Get active JWT session from Supabase
  const { data: { session } } = await supabase.auth.getSession();
  const token = session?.access_token;

  const res = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...(options.headers || {})
    }
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || 'API request failed');
  }
  return res.json();
}
```

---

## 2. API Endpoint Reference

### Root & System Health
- **`GET /`**: Welcome message & links to interactive docs.
- **`GET /supabase/test-connection`**: Verify Supabase client connection status.

### Authentication & Session (`/auth`)
- **`POST /auth/signup`**: Register a new user with email & password.
- **`POST /auth/signin`**: Authenticate user and obtain JWT Bearer session token.
- **`GET /auth/me`**: Verify Bearer token and return current user details.

### Profiles API (`/rest/v1/profiles`)
- **`GET /rest/v1/profiles?id=eq.{user_id}`**: Retrieve user profile (`id`, `email`, `full_name`, `chess_rating`, `checkers_rating`, `avatar_url`).
- **`PATCH /rest/v1/profiles?id=eq.{user_id}`**: Update profile attributes (`full_name`, `chess_rating`, `checkers_rating`, `avatar_url`).
- **`GET /profiles/me`** / **`PUT /profiles/me`**: Convenience endpoints for the authenticated user profile.

### Tournaments CRUD API (`/rest/v1/tournaments`)
- **`POST /rest/v1/tournaments`**: Create a tournament (`title`, `game_type`, `format`, `time_control`, `start_date`, `start_time`, `rounds_count`, etc.).
- **`GET /rest/v1/tournaments?select=*`**: List visible tournaments (RLS supported).
- **`GET /rest/v1/tournaments/{tournament_id}`**: Get single tournament details.
- **`PATCH /rest/v1/tournaments?id=eq.{tournament_id}`**: Update tournament settings.
- **`DELETE /rest/v1/tournaments?id=eq.{tournament_id}`**: Archive or delete tournament.

### Participants, Admittance & Invites (`/rest/v1/participants`, `/functions/v1/send-invite`)
- **`POST /rest/v1/participants`**: Add participant (`tournament_id`, `user_id`, `email`, `status`).
- **`GET /rest/v1/participants?tournament_id=eq.{tournament_id}&select=*`**: Participant roster feed.
- **`PATCH /rest/v1/participants?id=eq.{participant_id}`**: Approve admission (`status: 'Approved'`).
- **`DELETE /rest/v1/participants?id=eq.{participant_id}`**: Remove participant from roster.
- **`POST /functions/v1/send-invite`**: Dispatch email invite (`email`, `tournament_id`, `invite_link`).

### Tournament Administrators API (`/rest/v1/tournament_admins`)
- **`GET /rest/v1/tournament_admins?tournament_id=eq.{tournament_id}&select=*`**: List tournament admins.
- **`POST /rest/v1/tournament_admins`**: Assign admin/moderator (`tournament_id`, `user_id`, `role: 'co-admin' | 'moderator'`).
- **`DELETE /rest/v1/tournament_admins?id=eq.{admin_id}`**: Revoke admin privileges.

### Ocheso for Platforms (`/v1/orgs`, `/v1/platform`, `/v1/embed`, `/v1/internal`)
Third-party tournaments: organisations, email invites, embeds, autopilot. The
contract is `docs/OCHESO_PLATFORMS.md` (section D); the database side is
`db/platforms.sql`. Every error answers `{detail, code}`.

| Who | How they authenticate | Routes |
|---|---|---|
| Studio (organisers) | Supabase JWT | `/v1/orgs/*` (org, team, keys, webhooks, series, players, installs, usage, activity), `POST /v1/orgs/bootstrap`, `/v1/tournaments/{slug}/invites`, `/v1/tournaments/{slug}/autopilot[/pause\|resume\|start-now\|pair-now\|extend-break]`, `/v1/invites/{id}[/resend]` |
| Players (accounts) | Supabase JWT | `GET /v1/me` (also claims invites: `claimed`), `/v1/me/invites`, `/v1/invites/by-token/{token}/accept\|decline`, `/v1/me/embed-sessions` |
| A partner's server | `Authorization: Bearer ochs_...` (never with an `Origin` header) | `/v1/platform/*`: player tokens, tournaments, players, roster/rounds/standings, erasure; `Idempotency-Key` on POSTs |
| The embed frame | `X-Ocheso-Session: oche_...` | `/v1/embed/t/{slug}/me\|join\|withdraw\|arena/*`, `/v1/embed/games/{id}[/move\|flag\|resign\|draw\|draw/decline]` |
| Anyone | nothing (cacheable, `Access-Control-Allow-Origin: *`) | `/v1/embed/t/{slug}`, `/v1/embed/o/{org}[/series/{s}]`, `/v1/embed/g/{id}`, `/v1/embed/policy`, `/v1/embed/ping`, `/v1/invites/by-token/{token}` |
| The database | `X-Ocheso-Tick` (HMAC of the raw body) | `POST /v1/internal/tick` |

Tokens (`ochs_`, `ochp_`, `oche_`) never reach PostgREST as bearers - routes
that take a sign-in token refuse them with 401 `wrong_token` - and travel to
the database only as SHA-256 hashes inside a request this API signs with
`REFEREE_SECRET`. Mail is optional: set `RESEND_API_KEY` and `MAIL_FROM` (a
verified sender, e.g. `Ocheso <invites@ocheso.com>`) and the autopilot tick
sends queued invitations through Resend; without them mail stays queued and
`GET /health` says `"mail": "off"`. These are Resend settings, never Supabase
keys - the API still refuses to start with a service-role key.

---

## 3. Local Development & Testing

1. **Install everything both functions need, plus the server and tests**:
   ```bash
   pip install -r requirements-dev.txt
   ```

2. **Configure Environment Variables**: create `.env` from `.env.example`
   (`SUPABASE_URL`, `SUPABASE_ANON_KEY` - the public key only - and
   `REFEREE_SECRET`; optionally `RESEND_API_KEY` and `MAIL_FROM` for mail).

3. **Run the whole API locally** (both functions in one process):
   ```bash
   uvicorn dev:app --reload --port 8000
   ```

4. **Tests**:
   ```bash
   pytest                      # unit tests (tests/)
   db/test/e2e_play.sh         # tournaments end to end, local Postgres + PostgREST
   db/test/e2e_agents.sh       # agents end to end, with the real engines
   db/test/e2e_platforms.sh    # Ocheso for Platforms end to end, ticks made by the database
   db/test/test_db.sh          # the database suites, each on a fresh database
   ```

---

## 4. Deployment & Git

Two Vercel functions in one project, one domain, both in `dub1` beside the
database (`vercel.json`, Vercel Services):

| Function | Serves | Root | Dependencies |
|---|---|---|---|
| `core` | everything else - tournaments, play, accounts, Ocheso for Platforms (up to 60 s: the autopilot tick) | `core/` | `core/requirements.txt` |
| `agents` | `/v1/agents`, `/v1/agent-keys`, `/v1/connect` | repository | `requirements.txt` (+ Stockfish in `agents/bin`, Maia in `agents/models/maia-npz`) |

The agents function stays under Vercel's 225 MB so it ships whole: nothing is
installed or downloaded at cold start. `tests/test_split.py` holds the split.

- Repository: [https://github.com/JOELEVIC/ocheso-api](https://github.com/JOELEVIC/ocheso-api)
- Domain: `api.ocheso.com`

---

## 5. Changelog

### Ocheso for Platforms (unreleased)

Behaviour changes for existing tournaments and accounts, beyond the new
`/v1/orgs`, `/v1/platform`, `/v1/embed` and `/v1/internal` routes:

- **Clocks are flagged automatically in every tournament.** Once
  `private.platform_settings.autopilot_enabled` is on, the autopilot tick ends
  any live game whose side to move has run out of time - in personal
  tournaments too, and in tournaments without autopilot - where organisers used
  to wait for someone to claim the flag (`private.expired_games`, `sys-flag`;
  docs/OCHESO_PLATFORMS.md C8). The result is the one a claim would have
  given (`rules.flag_result`: a loss on time - in chess a draw when the
  opponent could never mate).
- **Joining a team takes a yes.** A staff invitation (`invite_org_member`) is
  accepted from its email - the invitation page, `accept_invite` - and is
  no longer claimed just by signing in with that address, unlike tournament
  invitations. A member can be handed an organisation and cannot delete their
  account until they leave it, so nobody is made one without asking.
- **Invitation links go to a partner's page only on a listed origin.** The
  "I'm in" button links to the page where the embed was seen only when that
  origin is on the organisation's own `allowed_origins`; otherwise, and always
  for an empty list, it is the hosted page `/o/{org}/{slug}?invite=`.
- **Re-adding an address keeps its mail history.** Revoking an invite and
  adding the address again counts as a resend (three at most, an hour apart),
  and one sender mails one address at most 10 invitations a day.

