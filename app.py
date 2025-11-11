import os
import uuid
import sqlite3
import random
import string
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-for-testing'
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'imageshare.db')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
# Set maximum shares limit via environment; defaults to 100 if not provided
app.config['MAX_SHARES'] = int(os.environ.get('MAX_SHARES', 100))

# Configure ProxyFix to get real client IP addresses behind Caddy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('templates', exist_ok=True)
os.makedirs('static/css', exist_ok=True)

# Database functions
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript('''
    DROP TABLE IF EXISTS users;
    DROP TABLE IF EXISTS image_shares;
    DROP TABLE IF EXISTS images;
    DROP TABLE IF EXISTS access_logs;
    
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );
    
    CREATE TABLE image_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        share_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    
    CREATE TABLE images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        share_id INTEGER NOT NULL,
        FOREIGN KEY (share_id) REFERENCES image_shares (id)
    );
    
    CREATE TABLE access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        share_id INTEGER NOT NULL,
        access_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        user_agent TEXT,
        FOREIGN KEY (share_id) REFERENCES image_shares (id)
    );
    ''')
    
    # Create admin user
    cursor = db.cursor()
    admin_password = os.environ.get('ADMIN_PASSWORD', 'admin')
    cursor.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        ('admin', generate_password_hash(admin_password))
    )
    db.commit()

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def generate_short_id(length=6):
    """Generate a short random ID for shareable URLs"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/')
# 简单的测试路由，用于直接删除所有共享
@app.route('/test_delete_all', methods=['POST'])
@login_required
def test_delete_all():
    # Check confirmation text
    confirm_text = request.form.get('confirm_text', '')
    if confirm_text.upper() != 'DELETE':
        flash('Invalid confirmation text. Please type "DELETE" exactly.')
        return redirect(url_for('dashboard'))
    
    db = get_db()
    # Get all shares for the current user
    shares = db.execute('SELECT id FROM image_shares WHERE user_id = ?', 
                      (session['user_id'],)).fetchall()
    
    if shares:
        # Get all images for these shares
        share_ids = [share['id'] for share in shares]
        if share_ids:
            # Get all image filenames to delete
            images = db.execute(
                'SELECT filename FROM images WHERE share_id IN ({})'.format(
                    ','.join(['?'] * len(share_ids))
                ),
                share_ids
            ).fetchall()
            
            # Delete image files from filesystem
            for image in images:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image['filename']))
                except Exception as e:
                    print(f"Error deleting file {image['filename']}: {e}")
            
            # Delete all images associated with these shares
            db.execute(
                'DELETE FROM images WHERE share_id IN ({})'.format(
                    ','.join(['?'] * len(share_ids))
                ),
                share_ids
            )
            
            # Delete all shares
            db.execute(
                'DELETE FROM image_shares WHERE id IN ({})'.format(
                    ','.join(['?'] * len(share_ids))
                ),
                share_ids
            )
            
            db.commit()
            flash('All shares and associated files have been deleted')
        else:
            flash('No shares found to delete')
    else:
        flash('No shares found to delete')
    
    return redirect(url_for('dashboard'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    db = get_db()
    new_url = request.args.get('new_url')
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'change_admin_password':
            new_password = request.form.get('new_admin_password')
            confirm_password = request.form.get('confirm_admin_password')

            if not new_password:
                flash('Please enter a new admin password')
            elif new_password != confirm_password:
                flash('Admin passwords do not match')
            else:
                db.execute(
                    'UPDATE users SET password_hash = ? WHERE id = ?',
                    (generate_password_hash(new_password), session['user_id'])
                )
                db.commit()
                flash('Admin password updated successfully')
        
        elif action == 'delete_all_shares':
            # Get all shares for the current user
            shares = db.execute('SELECT id FROM image_shares WHERE user_id = ?', 
                              (session['user_id'],)).fetchall()
            
            if shares:
                # Get all images for these shares
                share_ids = [share['id'] for share in shares]
                if share_ids:
                    # Get all image filenames to delete
                    images = db.execute(
                        'SELECT filename FROM images WHERE share_id IN ({})'.format(
                            ','.join(['?'] * len(share_ids))
                        ),
                        share_ids
                    ).fetchall()
                    
                    # Delete image files from filesystem
                    for image in images:
                        try:
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image['filename']))
                        except Exception as e:
                            # Log error but continue with other deletions
                            print(f"Error deleting file {image['filename']}: {e}")
                    
                    # Delete all images associated with these shares
                    db.execute(
                        'DELETE FROM images WHERE share_id IN ({})'.format(
                            ','.join(['?'] * len(share_ids))
                        ),
                        share_ids
                    )
                    
                    # Delete all shares
                    db.execute(
                        'DELETE FROM image_shares WHERE id IN ({})'.format(
                            ','.join(['?'] * len(share_ids))
                        ),
                        share_ids
                    )
                    
                    db.commit()
                    flash('All shares and associated files have been deleted')
                else:
                    flash('No shares found to delete')
            else:
                flash('No shares found to delete')

        return redirect(url_for('dashboard'))

    shares = db.execute('SELECT * FROM image_shares WHERE user_id = ? ORDER BY created_at DESC', 
                      (session['user_id'],)).fetchall()
    
    # Add images count and views count to each share
    for share in shares:
        # Count images for this share
        images_count = db.execute('SELECT COUNT(*) FROM images WHERE share_id = ?', (share['id'],)).fetchone()[0]
        # Count views (access logs) for this share
        views_count = db.execute('SELECT COUNT(*) FROM access_logs WHERE share_id = ?', (share['id'],)).fetchone()[0]
        
        # Add attributes to the share object
        share['images'] = []  # Just for template compatibility
        share['views_count'] = views_count
    return render_template('dashboard.html', shares=shares, new_url=new_url)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        title = request.form.get('title')
        password = request.form.get('password')
        
        if not title:
            flash('Title is required')
            return redirect(url_for('upload'))
        
        files = request.files.getlist('images')
        if not files or files[0].filename == '':
            flash('No images selected')
            return redirect(url_for('upload'))
        
        # Limit to 10 images per share
        if len(files) > 10:
            flash('Maximum 10 images allowed per share')
            return redirect(url_for('upload'))
        
        # Check each file size (5MB limit)
        for file in files:
            if file and allowed_file(file.filename):
                # Get file size
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)  # Reset file position
                
                if file_size > 5 * 1024 * 1024:  # 5MB in bytes
                    flash(f'Image {file.filename} exceeds 5MB limit')
                    return redirect(url_for('upload'))
        
        # Check if user has reached maximum shares limit
        db = get_db()
        current_shares_count = db.execute(
            'SELECT COUNT(*) FROM image_shares WHERE user_id = ?', 
            (session['user_id'],)
        ).fetchone()[0]
        
        # If reached limit, delete the oldest share to make room
        if current_shares_count >= app.config['MAX_SHARES']:
            # Get the oldest share
            oldest_share = db.execute(
                'SELECT id FROM image_shares WHERE user_id = ? ORDER BY created_at ASC LIMIT 1',
                (session['user_id'],)
            ).fetchone()
            
            if oldest_share:
                oldest_share_id = oldest_share['id']
                
                # Delete associated images from filesystem and database
                images = db.execute('SELECT filename FROM images WHERE share_id = ?', (oldest_share_id,)).fetchall()
                for image in images:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image['filename']))
                    except Exception as e:
                        print(f"Error deleting file {image['filename']}: {e}")
                
                # Delete images from database
                db.execute('DELETE FROM images WHERE share_id = ?', (oldest_share_id,))
                
                # Delete access logs
                db.execute('DELETE FROM access_logs WHERE share_id = ?', (oldest_share_id,))
                
                # Delete the share
                db.execute('DELETE FROM image_shares WHERE id = ?', (oldest_share_id,))
                db.commit()
                flash('Your oldest share has been automatically deleted to make room for new uploads')
        
        # Create share
        share_id = generate_short_id(3)  # 3-character short ID
        db = get_db()
        cursor = db.cursor()
        
        # Simple check for duplicates
        while cursor.execute('SELECT id FROM image_shares WHERE share_id = ?', (share_id,)).fetchone():
            share_id = generate_short_id(3)
            
        cursor.execute(
            'INSERT INTO image_shares (share_id, title, password_hash, user_id) VALUES (?, ?, ?, ?)',
            (share_id, title, generate_password_hash(password) if password else '', session['user_id'])
        )
        share_db_id = cursor.lastrowid
        
        # Save images
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                
                cursor.execute(
                    'INSERT INTO images (filename, original_filename, share_id) VALUES (?, ?, ?)',
                    (unique_filename, filename, share_db_id)
                )
        
        db.commit()
        share_url = url_for("view_share", share_id=share_id, _external=True, _scheme='https')
        return redirect(url_for('dashboard', new_url=share_url))
    
    return render_template('upload.html')

@app.route('/manage/<int:share_id>', methods=['GET', 'POST'])
@login_required
def manage(share_id):
    db = get_db()
    share = db.execute('SELECT * FROM image_shares WHERE id = ?', (share_id,)).fetchone()
    
    if not share or share['user_id'] != session['user_id']:
        flash('You do not have permission to manage this share')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update':
            title = request.form.get('title')
            password = request.form.get('password')
            
            if title:
                db.execute('UPDATE image_shares SET title = ? WHERE id = ?', (title, share_id))
            
            if password:
                db.execute('UPDATE image_shares SET password_hash = ? WHERE id = ?', 
                         (generate_password_hash(password), share_id))
            
            db.commit()
            flash('Share updated successfully')
        
        elif action == 'delete':
            # Delete associated images from filesystem
            images = db.execute('SELECT filename FROM images WHERE share_id = ?', (share_id,)).fetchall()
            for image in images:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image['filename']))
                except:
                    pass
            
            db.execute('DELETE FROM images WHERE share_id = ?', (share_id,))
            db.execute('DELETE FROM image_shares WHERE id = ?', (share_id,))
            db.commit()
            
            flash('Share deleted successfully')
            return redirect(url_for('dashboard'))
        
        elif action == 'delete_image':
            image_id = request.form.get('image_id')
            image = db.execute('SELECT * FROM images WHERE id = ?', (image_id,)).fetchone()
            
            if image and image['share_id'] == share_id:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image['filename']))
                except:
                    pass
                
                db.execute('DELETE FROM images WHERE id = ?', (image_id,))
                db.commit()
                flash('Image deleted successfully')

        
    
    images = db.execute('SELECT * FROM images WHERE share_id = ?', (share_id,)).fetchall()
    return render_template('manage.html', share=share, images=images)

@app.route('/s/<share_id>', methods=['GET', 'POST'])
def view_share(share_id):
    # Skip logging for favicon requests
    if request.path.endswith('/favicon.ico'):
        return redirect(url_for('static', filename='favicon.ico'))
    
    db = get_db()
    share = db.execute('SELECT * FROM image_shares WHERE share_id = ?', (share_id,)).fetchone()
    
    if not share:
        return "Share not found", 404
    
    # Check if already authenticated for this share (for password-protected shares)
    is_authenticated = session.get(f'share_auth_{share_id}')
    
    # For non-password protected shares or already authenticated access
    if not share['password_hash'] or is_authenticated:
        # Create a unique key for this share view in the session
        view_key = f'viewed_{share_id}'
        current_time = datetime.now()
        
        # Only log access if this is a new view (not logged in the last 5 minutes)
        if view_key not in session or (current_time - datetime.fromisoformat(session[view_key])).seconds > 300:
            # Record the access time in session to prevent duplicates
            session[view_key] = current_time.isoformat()
            
            # Get current timestamp for database
            db_timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S.%f")
            
            # Log access directly here to ensure it only happens once
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO access_logs (share_id, ip_address, user_agent, access_time) VALUES (?, ?, ?, ?)',
                (share['id'], request.remote_addr, request.user_agent.string, db_timestamp)
            )
            db.commit()
            print(f"Access logged for share_id {share['id']} at {db_timestamp}")
        
        images = db.execute('SELECT * FROM images WHERE share_id = ?', (share['id'],)).fetchall()
        return render_template('view.html', share=share, images=images)
    
    if request.method == 'POST':
        password = request.form.get('password')
        
        if check_password_hash(share['password_hash'], password):
            session[f'share_auth_{share_id}'] = True
            
            # Log access once after successful password authentication
            current_time = datetime.now()
            db_timestamp = current_time.strftime("%Y-%m-%d %H:%M:%S.%f")
            cursor = db.cursor()
            cursor.execute(
                'INSERT INTO access_logs (share_id, ip_address, user_agent, access_time) VALUES (?, ?, ?, ?)',
                (share['id'], request.remote_addr, request.user_agent.string, db_timestamp)
            )
            db.commit()
            print(f"Access logged after password auth for share_id {share['id']} at {db_timestamp}")
            
            # Also record in session to prevent duplicates
            session[f'viewed_{share_id}'] = current_time.isoformat()
            
            images = db.execute('SELECT * FROM images WHERE share_id = ?', (share['id'],)).fetchall()
            return render_template('view.html', share=share, images=images)
        else:
            flash('Invalid password')
    
    return render_template('password.html', share=share)

def log_access(db, share_id):
    """Log access to a share, preventing duplicate counts from the same client within a short timeframe"""
    # Skip logging for favicon or other resource requests
    if request.path.endswith('/favicon.ico') or request.path.startswith('/static/'):
        return
    
    # Generate a client identifier (simplified approach using IP + user agent)
    client_id = f"{request.remote_addr}:{hash(request.user_agent.string)}"
    
    # Check if this client has accessed this share within the last 5 minutes
    cursor = db.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM access_logs WHERE share_id = ? AND ip_address = ? AND "
        "datetime(access_time) > datetime('now', '-5 minutes')",
        (share_id, request.remote_addr)
    )
    recent_access_count = cursor.fetchone()[0]
    
    # Only log if no recent access from this client
    if recent_access_count == 0:
        # Get current timestamp
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        
        cursor.execute(
            'INSERT INTO access_logs (share_id, ip_address, user_agent, access_time) VALUES (?, ?, ?, ?)',
            (share_id, request.remote_addr, request.user_agent.string, current_time)
        )
        db.commit()
        print(f"Access logged for share_id {share_id} from client {client_id} at {current_time}")
    else:
        print(f"Skipping duplicate access log for share_id {share_id} from client {client_id}")

# Initialize database before first request
@app.before_first_request
def before_first_request():
    init_db()
    print('Database initialized.')

if __name__ == '__main__':
    app.run(debug=True)
