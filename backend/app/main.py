from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Depends, HTTPException, status, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import Response
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import List, Dict, Any, Optional

from . import models, schemas, security
from .database import SessionLocal, engine
from .security import (
    get_password_hash, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES,
    verify_password, oauth2_scheme, decode_access_token
)

import spotipy
from spotipy.exceptions import SpotifyException
from spotipy.oauth2 import SpotifyClientCredentials

# --- Database setup ---
models.Base.metadata.create_all(bind=engine)

# --- App & CORS ---
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://vibe-list-playlist-suggestor.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Middleware for logs ---
@app.middleware("http")
async def log_requests(request: Request, call_next):
    origin = request.headers.get("origin")
    method = request.method
    path = request.url.path
    print(f"[REQ] {method} {path} Origin={origin}")
    response = await call_next(request)
    return response

# --- Root health check ---
@app.get("/")
def health_check():
    return {"status": "ok"}

# --- OPTIONS handler for preflight ---
@app.options("/{full_path:path}")
def preflight_handler(full_path: str):
    return Response(status_code=204, content=None)

# --- Spotify setup ---
try:
    auth_manager = SpotifyClientCredentials()
    sp = spotipy.Spotify(auth_manager=auth_manager)
    print("✅ Spotify authentication successful.")
except Exception as e:
    print(f"❌ Spotify authentication failed: {e}")
    sp = None

# --- DB dependency ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Auth helper ---
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"},
    )
    email = decode_access_token(token, credentials_exception)
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# --- Register ---
@app.post("/register", response_model=schemas.User)
@app.post("/register/", response_model=schemas.User)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# --- Token login ---
@app.post("/token", response_model=schemas.Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

# --- User routes ---
@app.get("/users/me/", response_model=schemas.User)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user

@app.post("/users/me/playlists", response_model=schemas.UserPlaylist)
def save_playlist_for_user(
    playlist: schemas.PlaylistCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)
):
    db_playlist = models.UserPlaylist(**playlist.dict(), owner_id=current_user.id)
    db.add(db_playlist)
    db.commit()
    db.refresh(db_playlist)
    return db_playlist

@app.get("/users/me/playlists", response_model=List[schemas.UserPlaylist])
def read_user_playlists(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return current_user.playlists

# --- Spotify Suggestion ---
@app.post("/suggest", response_model=schemas.SuggestionResponse)
def get_suggestions(request: schemas.SuggestionRequest):
    global sp
    if not sp:
        raise HTTPException(status_code=503, detail="Spotify service is unavailable.")
    query = f"{request.mood} {request.genre}"
    if request.language != "Any":
        query += f" {request.language}"
    try:
        results = sp.search(q=query, type="playlist", limit=12)
        spotify_playlists = results.get("playlists", {}).get("items", [])
        playlists = [
            schemas.PlaylistBase(
                name=item.get("name", "Untitled Playlist"),
                owner=item.get("owner", {}).get("display_name", "Unknown"),
                spotify_url=item.get("external_urls", {}).get("spotify"),
                image_url=item.get("images", [{}])[0].get("url"),
            )
            for item in spotify_playlists if item.get("external_urls", {}).get("spotify")
        ]
        return schemas.SuggestionResponse(playlists=playlists)
    except SpotifyException as e:
        raise HTTPException(status_code=502, detail=f"Spotify error: {e.msg}")
    except Exception:
        raise HTTPException(status_code=500, detail="An internal error occurred.")
