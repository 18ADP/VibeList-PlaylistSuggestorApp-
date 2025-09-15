from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    playlists = relationship("UserPlaylist", back_populates="owner")

class UserPlaylist(Base):
    __tablename__ = "user_playlists"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    spotify_url = Column(String)
    image_url = Column(String, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="playlists")