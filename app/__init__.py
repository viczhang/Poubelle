import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from werkzeug.middleware.proxy_fix import ProxyFix

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-for-testing')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///imageshare.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
    app.config['SITE_TITLE'] = os.environ.get('SITE_TITLE', 'Poubelle')
    
    # Configure ProxyFix to get real client IP addresses behind Caddy
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
    
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
    
    # Root route - redirect based on authentication status
    @app.route('/')
    def index():
        from flask import redirect, url_for
        from flask_login import current_user
        
        if current_user.is_authenticated:
            return redirect(url_for('admin.dashboard'))
        else:
            return redirect(url_for('auth.login'))
    
    # Catch-all route for @vite/client to prevent 404 errors
    @app.route('/@vite/client')
    def vite_client():
        # Return empty response with 204 No Content status
        from flask import make_response
        return make_response('', 204)
    
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        from app.models import User
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin')
            admin_password = os.environ.get('ADMIN_PASSWORD', 'admin')
            admin.set_password(admin_password)
            db.session.add(admin)
            db.session.commit()
    
    return app
