import os

SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_super_secret_key_here' # Change this in production!
SQLALCHEMY_DATABASE_URI = 'sqlite:///data_access_tracker.db' # SQLite database file
SQLALCHEMY_TRACK_MODIFICATIONS = False