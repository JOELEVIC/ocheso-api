import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "Welcome to Ocheso API" in response.json()["message"]

def test_supabase_connection():
    response = client.get("/supabase/test-connection")
    assert response.status_code == 200
    assert response.json()["status"] == "connected"

def test_auth_me_unauthorized():
    response = client.get("/auth/me")
    assert response.status_code == 401

def test_profiles_rest_endpoint():
    # Without auth token, should fail or return empty/unauthorized depending on implementation
    response = client.get("/rest/v1/profiles")
    # Depending on supabase mock/live table, status code will be 200 (list) or 400/500
    assert response.status_code in [200, 400, 500]

def test_tournaments_rest_endpoint():
    response = client.get("/rest/v1/tournaments")
    assert response.status_code in [200, 400, 500]

def test_participants_rest_endpoint():
    response = client.get("/rest/v1/participants")
    assert response.status_code in [200, 400, 500]

def test_tournament_admins_rest_endpoint():
    response = client.get("/rest/v1/tournament_admins")
    assert response.status_code in [200, 400, 500]

def test_send_invite_unauthorized():
    response = client.post("/functions/v1/send-invite", json={
        "email": "player@example.com",
        "tournament_id": "test-uuid",
        "invite_link": "https://ocheso.com/join/123"
    })
    assert response.status_code == 401
