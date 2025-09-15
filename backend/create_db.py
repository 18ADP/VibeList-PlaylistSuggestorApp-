# backend/create_db.py

from app.database import engine
# Import the correct models that actually exist in your models.py file
from app.models import Base, User, UserPlaylist

def setup_database():
    """
    Creates all database tables defined in models.py.
    """
    print("Dropping all tables if they exist...")
    # Optional: This drops all tables first, useful for a clean slate during development
    Base.metadata.drop_all(bind=engine)
    
    print("Creating database tables (users, user_playlists)...")
    # This creates the tables based on your current models
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully.")

if __name__ == "__main__":
    setup_database()