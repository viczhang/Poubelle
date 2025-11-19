from datetime import datetime
import uuid
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from app import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ImageShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    share_id = db.Column(db.String(3), unique=True, index=True)
    
    def __init__(self, *args, **kwargs):
        # Generate a short ID if not provided
        if 'share_id' not in kwargs:
            kwargs['share_id'] = self.generate_short_id()
        super(ImageShare, self).__init__(*args, **kwargs)
    
    @classmethod
    def generate_short_id(cls, length=3):
        """Generate a unique short ID with the specified length."""
        characters = string.ascii_letters + string.digits
        
        # Try generating until we find a unique ID
        max_attempts = 100
        for _ in range(max_attempts):
            # Generate random ID
            short_id = ''.join(random.choice(characters) for _ in range(length))
            
            # Check if ID already exists
            existing = cls.query.filter_by(share_id=short_id).first()
            if not existing:
                return short_id
        
        # Fallback to UUID if we can't find a unique short ID
        return str(uuid.uuid4())
    title = db.Column(db.String(100))
    text_content = db.Column(db.Text, nullable=True)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    images = db.relationship('Image', backref='share', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        if password:
            self.password_hash = generate_password_hash(password)
        else:
            self.password_hash = None
        
    def check_password(self, password):
        if not self.password_hash:
            return True
        return check_password_hash(self.password_hash, password)

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    original_filename = db.Column(db.String(100))
    file_type = db.Column(db.String(20), default='image')  # image, video, text
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    share_id = db.Column(db.Integer, db.ForeignKey('image_share.id'))

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    share_id = db.Column(db.Integer, db.ForeignKey('image_share.id'))
    access_time = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(255))
    
    share = db.relationship('ImageShare', backref=db.backref('access_logs', lazy='dynamic'))
