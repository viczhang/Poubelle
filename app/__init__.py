import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-for-testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///imageshare.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
    
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    
    from app.models import User
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    from app.routes.auth import auth as auth_blueprint
    from app.routes.admin import admin as admin_blueprint
    from app.routes.share import share as share_blueprint
    
    app.register_blueprint(auth_blueprint)
    app.register_blueprint(admin_blueprint)
    app.register_blueprint(share_blueprint)
    
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        from app.models import User
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin')
            admin.set_password('admin')  # Default password, should be changed
            db.session.add(admin)
            db.session.commit()
    
    return app