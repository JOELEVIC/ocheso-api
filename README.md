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

---

## 3. Local Development & Testing

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Environment Variables**:
   Create a `.env` file based on `.env.example`:
   ```env
   SUPABASE_URL=https://ofjnhbkdqipqheyzdvym.supabase.co
   SUPABASE_KEY=your-supabase-anon-key
   ```

3. **Run the API Server Locally**:
   ```bash
   uvicorn main:app --reload --port 8000
   ```

4. **Run Unit & Integration Tests**:
   ```bash
   PYTHONPATH=. pytest
   ```

---

## 4. Deployment & Git

- Repository: [https://github.com/JOELEVIC/ocheso-api](https://github.com/JOELEVIC/ocheso-api)
- Domain: `api.ocheso.com`
