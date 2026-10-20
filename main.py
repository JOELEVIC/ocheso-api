from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routers import auth, profiles, tournaments, participants, tournament_admins, supabase_ops

app = FastAPI(
    title="Ocheso API & Supabase Backend",
    description="Backend API for Ocheso tournament console and user flows, integrated with Supabase.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(profiles.router)
app.include_router(tournaments.router)
app.include_router(participants.router)
app.include_router(tournament_admins.router)
app.include_router(supabase_ops.router)

@app.get("/", tags=["Root"])
def read_root():
    return {
        "message": "Welcome to Ocheso API & Supabase Backend!",
        "docs": "/docs",
        "redoc": "/redoc"
    }
