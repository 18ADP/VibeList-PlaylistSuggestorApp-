from pydantic import BaseModel
from typing import List, Optional

class PlaylistBase(BaseModel):
    name: str
    owner: str
    spotify_url: str
    image_url: Optional[str] = None

class SuggestionRequest(BaseModel):
    mood: str
    genre: str
    language: str

class SuggestionResponse(BaseModel):
    playlists: List[PlaylistBase]

class UserCreate(BaseModel):
    email: str
    password: str

class User(BaseModel):
    id: int
    email: str
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class PlaylistCreate(BaseModel):
    name: str
    spotify_url: str
    image_url: Optional[str] = None

class UserPlaylist(PlaylistCreate):
    id: int
    owner_id: int
    class Config:
        from_attributes = True