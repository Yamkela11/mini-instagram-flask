from werkzeug.utils import secure_filename
import os

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class Config:
    # Replace the secret key below with your own strong random key
    SECRET_KEY = 'a_very_strong_and_random_secret_key_here'

    SQLALCHEMY_DATABASE_URI = 'sqlite:///mini_instagram.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static/uploads')
    MAX_CONTENT_LENGTH = 150 * 1024 * 1024  # Max 150MB upload size
