from datetime import datetime
import uuid
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
    share_id = db.Column(db.String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    title = db.Column(db.String(100))
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
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
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    share_id = db.Column(db.Integer, db.ForeignKey('image_share.id'))
