# --- Load environment variables ---
from dotenv import load_dotenv
load_dotenv()

# --- FastAPI & dependencies ---
from fastapi import FastAPI, Depends, HTTPException, status, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import timedelta
from typing import List, Dict, Any, Optional

# --- Local imports ---
from . import models, schemas, security
from .database import SessionLocal, engine
from .security import (
    get_password_hash, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES,
    verify_password, oauth2_scheme, decode_access_token
)

# --- Spotify Imports ---
import spotipy
from spotipy.exceptions import SpotifyException
from spotipy.oauth2 import SpotifyClientCredentials


# --- Database Setup ---
models.Base.metadata.create_all(bind=engine)

# --- App & CORS Configuration ---
app = FastAPI()

# ✅ Use regex to automatically allow ALL your Vercel preview and production domains
# (so you never need to update CORS origins again)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https://vibe-list-playlist-suggestor.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Handle OPTIONS preflight globally to avoid CORS errors on non-GET/POST
@app.options("/{full_path:path}")
def preflight_handler(full_path: str, response: Response):
    # Let CORSMiddleware add the proper headers
    return Response(status_code=204)


# --- Spotify Authentication ---
try:
    auth_manager = SpotifyClientCredentials()
    sp = spotipy.Spotify(auth_manager=auth_manager)
    print("✅ Successfully authenticated with Spotify.")
except Exception as e:
    print(f"❌ Error authenticating with Spotify: {e}")
    sp = None


# --- Helper Function for Parsing Playlist Data ---
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
        name=playlist_name, owner=owner_name,
        spotify_url=spotify_url, image_url=image_url
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
        detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"},
    )
    email = decode_access_token(token, credentials_exception)
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


# --- Authentication Endpoints ---
@app.post("/register", response_model=schemas.User)
@app.post("/register/", response_model=schemas.User)  # 👈 Avoids redirect causing CORS issue
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
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}


# --- User Endpoints ---
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
            parsed for item in spotify_playlists if (parsed := parse_playlist_item(item)) is not None
        ]
        return schemas.SuggestionResponse(playlists=playlists)
    except SpotifyException as e:
        raise HTTPException(status_code=502, detail=f"Error communicating with Spotify: {e.msg}")
    except Exception as e:
        raise HTTPException(status_code=500, detail="An internal server error occurred.")
