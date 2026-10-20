# Ocheso API & Supabase Backend

A robust FastAPI backend built for the Ocheso tournament console and user flows, fully integrated with Supabase.

---

## Features & Endpoints

### 1. Authentication & Session (`/auth`)
- `POST /auth/signup`: Register user with Supabase Auth.
- `POST /auth/signin`: Authenticate user and obtain JWT Bearer token.
- `GET /auth/me`: Verify session and retrieve current user details.

### 2. Profiles API (`/rest/v1/profiles`)
- `GET /rest/v1/profiles?id=eq.{user_id}`: Retrieve user profile (`id`, `email`, `full_name`, `chess_rating`, `checkers_rating`, `avatar_url`).
- `PATCH /rest/v1/profiles?id=eq.{user_id}`: Update profile settings (`full_name`, `chess_rating`, `checkers_rating`, `avatar_url`).

### 3. Tournaments CRUD API (`/rest/v1/tournaments`)
- `POST /rest/v1/tournaments`: Create a new tournament.
- `GET /rest/v1/tournaments?select=*`: List visible tournaments (RLS supported).
- `GET /rest/v1/tournaments?id=eq.{tournament_id}`: Get single tournament details.
- `PATCH /rest/v1/tournaments?id=eq.{tournament_id}`: Update tournament configuration.
- `DELETE /rest/v1/tournaments?id=eq.{tournament_id}`: Archive or delete tournament.

### 4. Participants, Admittance & Invites (`/rest/v1/participants`, `/functions/v1/send-invite`)
- `POST /rest/v1/participants`: Add participant (`tournament_id`, `user_id`, `email`, `status`).
- `GET /rest/v1/participants?tournament_id=eq.{tournament_id}&select=*`: Participant roster feed.
- `PATCH /rest/v1/participants?id=eq.{participant_id}`: Approve admission request (`status: 'Approved'`).
- `DELETE /rest/v1/participants?id=eq.{participant_id}`: Remove participant from roster.
- `POST /functions/v1/send-invite`: Dispatch email invite (`email`, `tournament_id`, `invite_link`).

### 5. Tournament Administrators API (`/rest/v1/tournament_admins`)
- `GET /rest/v1/tournament_admins?tournament_id=eq.{tournament_id}&select=*`: List admins assigned to tournament.
- `POST /rest/v1/tournament_admins`: Assign admin (`tournament_id`, `user_id`, `role`).
- `DELETE /rest/v1/tournament_admins?id=eq.{admin_id}`: Revoke admin privileges.

---

## Getting Started & Running Tests

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Environment Variables**:
   Copy `.env.example` to `.env` and configure your Supabase URL and Key:
   ```env
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_KEY=your-supabase-anon-or-service-role-key
   ```

3. **Run the API Server**:
   ```bash
   uvicorn main:app --reload --port 8000
   ```

4. **Run Tests**:
   ```bash
   pytest
   ```

5. **Interactive Documentation**:
   - Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
   - ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## Pushing Online (Deployment)

To push this repository to GitHub or deploy to a cloud provider (such as Render, Railway, Fly.io, or Heroku):

1. Initialize git (if not already):
   ```bash
   git init
   git add .
   git commit -m "Initialize Ocheso API & Supabase Backend with tournaments, participants, admins, and profiles"
   ```

2. Add remote origin and push:
   ```bash
   git remote add origin https://github.com/your-username/ocheso-api.git
   git branch -M main
   git push -u origin main
   ```
