from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import List, Dict, Any, Optional
import re

# Spotify Imports
import spotipy
from spotipy.exceptions import SpotifyException
from spotipy.oauth2 import SpotifyClientCredentials

# FastAPI CORS
from starlette.middleware.cors import CORSMiddleware

# Local Imports
from . import models, schemas, security
from .database import SessionLocal, engine
from .security import (
    get_password_hash, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES,
    verify_password, oauth2_scheme, decode_access_token
)

# --- Database Setup ---
models.Base.metadata.create_all(bind=engine)

# --- App Initialization ---
app = FastAPI()

# --- Dynamic CORS Middleware (handles all your Vercel preview URLs) ---
class DynamicCORSMiddleware(CORSMiddleware):
    def is_allowed_origin(self, origin: str) -> bool:
        if not origin:
            return False
        allowed_patterns = [
            r"^https:\/\/vibe-list-playlist-suggestor-[a-z0-9]+-18adps-projects\.vercel\.app$",
            r"^https:\/\/vibe-list-playlist-suggestor-app\.vercel\.app$",
            r"^https:\/\/vibe-list-playlist-suggestor-app-git-main-18adps-projects\.vercel\.app$",
            r"^https:\/\/vibelist-playlistsuggester\.onrender\.com$"
        ]
        return any(re.match(pattern, origin) for pattern in allowed_patterns)

app.add_middleware(
    DynamicCORSMiddleware,
    allow_origins=["*"],  # Checked manually above
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Spotify API Authentication ---
try:
    auth_manager = SpotifyClientCredentials()
    sp = spotipy.Spotify(auth_manager=auth_manager)
    print("✅ Successfully authenticated with Spotify.")
except Exception as e:
    print(f"❌ Error authenticating with Spotify: {e}")
    sp = None


# --- Helper Function for Safer Data Parsing ---
def parse_playlist_item(item: Dict[str, Any]) -> Optional[schemas.PlaylistBase]:
    if not item:
        return None
    images = item.get('images', [])
    image_url = images[0]['url'] if images else None
    owner_data = item.get('owner', {})
    owner_name = owner_data.get('display_name', 'Unknown Artist')
    spotify_url = item.get('external_urls', {}).get('spotify')
    playlist_name = item.get('name', 'Untitled Playlist')
    if not spotify_url:
        return None
    return schemas.PlaylistBase(
        name=playlist_name,
        owner=owner_name,
        spotify_url=spotify_url,
        image_url=image_url
    )


# --- Dependencies ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    email = decode_access_token(token, credentials_exception)
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


# --- Authentication Endpoints ---
@app.post("/register", response_model=schemas.User)
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


@app.post("/token", response_model=schemas.Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# --- User Endpoints (Secured) ---
@app.get("/users/me/", response_model=schemas.User)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user


@app.post("/users/me/playlists", response_model=schemas.UserPlaylist)
def save_playlist_for_user(
    playlist: schemas.PlaylistCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    db_playlist = models.UserPlaylist(**playlist.dict(), owner_id=current_user.id)
    db.add(db_playlist)
    db.commit()
    db.refresh(db_playlist)
    return db_playlist


@app.get("/users/me/playlists", response_model=List[schemas.UserPlaylist])
def read_user_playlists(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    return current_user.playlists


# --- Public Suggestion Endpoint ---
@app.post("/suggest", response_model=schemas.SuggestionResponse)
def get_suggestions(request: schemas.SuggestionRequest):
    global sp
    if not sp:
        raise HTTPException(status_code=503, detail="Spotify service is unavailable.")
    query = f"{request.mood} {request.genre}"
    if request.language != "Any":
        query += f" {request.language}"
    print(f"🎧 Searching Spotify for: '{query}'")
    try:
        results = sp.search(q=query, type='playlist', limit=12)
        spotify_playlists = results.get('playlists', {}).get('items', [])
        playlists = [
            parsed for item in spotify_playlists
            if (parsed := parse_playlist_item(item)) is not None
        ]
        return schemas.SuggestionResponse(playlists=playlists)
    except SpotifyException as e:
        raise HTTPException(status_code=502, detail=f"Spotify API error: {e.msg}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


# --- Health Check Endpoint (for Render debugging) ---
@app.get("/")
def root():
    return {"status": "OK", "message": "VibeList backend running"}
