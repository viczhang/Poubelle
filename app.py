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
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'webm', 'avi', 'mov'}
# Set maximum shares limit via environment; defaults to 100 if not provided
app.config['MAX_SHARES'] = int(os.environ.get('MAX_SHARES', 100))
app.config['SITE_TITLE'] = os.environ.get('SITE_TITLE', 'Poubelle')

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
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    );
    
    CREATE TABLE IF NOT EXISTS image_shares (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        share_id TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,
        FOREIGN KEY (user_id) REFERENCES users (id)
    );
    
    CREATE TABLE IF NOT EXISTS images (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        share_id INTEGER NOT NULL,
        FOREIGN KEY (share_id) REFERENCES image_shares (id)
    );
    
    CREATE TABLE IF NOT EXISTS videos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        original_filename TEXT NOT NULL,
        uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        share_id INTEGER NOT NULL,
        FOREIGN KEY (share_id) REFERENCES image_shares (id)
    );
    
    CREATE TABLE IF NOT EXISTS text_content (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        share_id INTEGER NOT NULL,
        FOREIGN KEY (share_id) REFERENCES image_shares (id)
    );
    
    CREATE TABLE IF NOT EXISTS access_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        share_id INTEGER NOT NULL,
        access_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        ip_address TEXT,
        user_agent TEXT,
        FOREIGN KEY (share_id) REFERENCES image_shares (id)
    );
    ''')
    
    # Create admin user if not exists
    cursor = db.cursor()
    admin_exists = cursor.execute('SELECT id FROM users WHERE username = ?', ('admin',)).fetchone()
    if not admin_exists:
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
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/video/<filename>')
def serve_video(filename):
    """Custom video serving route with proper range support"""
    video_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(video_path):
        return "Video not found", 404
    
    # Security check - ensure filename is safe
    if not allowed_file(filename):
        return "Invalid video file", 400
    
    file_size = os.path.getsize(video_path)
    
    # Handle range requests for video streaming
    range_header = request.headers.get('Range', None)
    
    if range_header:
        # Parse range header
        try:
            range_match = range_header.replace('bytes=', '').split('-')
            start = int(range_match[0]) if range_match[0] else 0
            end = int(range_match[1]) if range_match[1] and range_match[1] != '' else file_size - 1
            
            # Ensure valid range
            start = max(0, start)
            end = min(file_size - 1, end)
            
            if start > end:
                return "Invalid range", 416
                
            content_length = end - start + 1
            
            def generate():
                with open(video_path, 'rb') as f:
                    f.seek(start)
                    bytes_to_read = content_length
                    while bytes_to_read > 0:
                        chunk_size = min(8192, bytes_to_read)
                        data = f.read(chunk_size)
                        if not data:
                            break
                        bytes_to_read -= len(data)
                        yield data
            
            response = app.response_class(generate(), mimetype='video/mp4')
            response.headers.add('Content-Range', f'bytes {start}-{end}/{file_size}')
            response.headers.add('Accept-Ranges', 'bytes')
            response.headers.add('Content-Length', str(content_length))
            response.headers.add('Cache-Control', 'public, max-age=3600')
            response.headers.add('Content-Disposition', f'inline; filename="{filename}"')
            response.headers.add('Access-Control-Allow-Origin', '*')
            response.headers.add('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
            response.headers.add('Access-Control-Allow-Headers', 'Range')
            response.headers.add('Access-Control-Expose-Headers', 'Accept-Ranges, Content-Range')
            response.status_code = 206  # Partial Content
            return response
            
        except (ValueError, IndexError):
            # If range parsing fails, fall back to full file
            pass
    
    # Serve full file if no range request
    def generate():
        with open(video_path, 'rb') as f:
            while True:
                data = f.read(8192)
                if not data:
                    break
                yield data
    
    response = app.response_class(generate(), mimetype='video/mp4')
    response.headers.add('Content-Length', str(file_size))
    response.headers.add('Accept-Ranges', 'bytes')
    response.headers.add('Cache-Control', 'public, max-age=3600')
    response.headers.add('Content-Disposition', f'inline; filename="{filename}"')
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Range')
    response.headers.add('Access-Control-Expose-Headers', 'Accept-Ranges, Content-Range')
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('admin.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            next_page = request.args.get('next')
            return redirect(next_page or url_for('admin.dashboard'))
        
        flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

# 简单的测试路由，用于直接删除所有共享
@app.route('/test_delete_all', methods=['POST'])
@login_required
def test_delete_all():
    # Check confirmation text
    confirm_text = request.form.get('confirm_text', '')
    if confirm_text.upper() != 'DELETE':
        flash('Invalid confirmation text. Please type "DELETE" exactly.')
        return redirect(url_for('admin.dashboard'))
    
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



@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        title = request.form.get('title')
        password = request.form.get('password')
        
        if not title:
            flash('Title is required')
            return redirect(url_for('upload'))
        
        # Get all content types
        image_files = []
        video_files = []
        
        # Collect all image files from array inputs
        for key in request.files:
            if key.startswith('image_files['):
                image_files.extend(request.files.getlist(key))
        
        # Collect all video files from array inputs
        for key in request.files:
            if key.startswith('video_files['):
                video_files.extend(request.files.getlist(key))
        
        text_content = request.form.get('text_content', '').strip()
        
        # Check if any content was provided
        has_images = any(image_files) and image_files[0].filename != ''
        has_videos = any(video_files) and video_files[0].filename != ''
        has_text = bool(text_content)
        
        if not has_images and not has_videos and not has_text:
            flash('Please provide at least one type of content (images, videos, or text)')
            return redirect(url_for('upload'))
        
        # Validate image files
        if has_images:
            if len(image_files) > 10:
                flash('Maximum 10 images allowed per share')
                return redirect(url_for('upload'))
            
            for file in image_files:
                if file and allowed_file(file.filename):
                    file.seek(0, os.SEEK_END)
                    file_size = file.tell()
                    file.seek(0)
                    
                    if file_size > 5 * 1024 * 1024:  # 5MB limit
                        flash(f'Image {file.filename} exceeds 5MB limit')
                        return redirect(url_for('upload'))
        
        # Validate video files
        if has_videos:
            if len(video_files) > 10:
                flash('Maximum 10 videos allowed per share')
                return redirect(url_for('upload'))
            
            for file in video_files:
                if file and allowed_file(file.filename):
                    file.seek(0, os.SEEK_END)
                    file_size = file.tell()
                    file.seek(0)
                    
                    if file_size > 10 * 1024 * 1024:  # 10MB limit
                        flash(f'Video {file.filename} exceeds 10MB limit')
                        return redirect(url_for('upload'))
        
        # Create share
        share_id = generate_short_id(3)  # 3-character short ID
        db = get_db()
        cursor = db.cursor()
        
        # Simple check for duplicates
        while cursor.execute('SELECT id FROM image_shares WHERE share_id = ?', (share_id,)).fetchone():
            share_id = generate_short_id(3)
            
        cursor.execute(
            'INSERT INTO image_shares (share_id, title, password_hash, user_id) VALUES (?, ?, ?, ?)',
            (share_id, title, generate_password_hash(password) if password else '', None)
        )
        share_db_id = cursor.lastrowid
        
        # Save images
        if has_images:
            for file in image_files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    unique_filename = f"{uuid.uuid4()}_{filename}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    file.save(file_path)
                    
                    cursor.execute(
                        'INSERT INTO images (filename, original_filename, share_id) VALUES (?, ?, ?)',
                        (unique_filename, filename, share_db_id)
                    )
        
        # Save videos
        if has_videos:
            for file in video_files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    unique_filename = f"{uuid.uuid4()}_{filename}"
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                    file.save(file_path)
                    
                    cursor.execute(
                        'INSERT INTO image (filename, original_filename, file_type, share_id) VALUES (?, ?, ?, ?)',
                        (unique_filename, filename, 'video', share_db_id)
                    )
        
        # Save text content
        if has_text:
            cursor.execute(
                'INSERT INTO text_content (content, share_id) VALUES (?, ?)',
                (text_content, share_db_id)
            )
        
        db.commit()
        share_url = url_for("view_share", share_id=share_id, _external=True)
        return render_template('upload_success.html', share_url=share_url)
    
    return render_template('upload.html')

@app.route('/manage/<int:share_id>', methods=['GET', 'POST'])
@login_required
def manage(share_id):
    db = get_db()
    share = db.execute('SELECT * FROM image_shares WHERE id = ?', (share_id,)).fetchone()
    
    if not share or share['user_id'] != session['user_id']:
        flash('You do not have permission to manage this share')
        return redirect(url_for('admin.dashboard'))
    
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
            return redirect(url_for('admin.dashboard'))
        
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
        
        images = db.execute('SELECT * FROM image WHERE share_id = ? AND file_type = ?', (share['id'], 'image')).fetchall()
        videos = db.execute('SELECT * FROM image WHERE share_id = ? AND file_type = ?', (share['id'], 'video')).fetchall()
        text_content = db.execute('SELECT * FROM text_content WHERE share_id = ?', (share['id'],)).fetchall()
        return render_template('view.html', share=share, images=images, videos=videos, text_content=text_content)
    
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
            videos = db.execute('SELECT * FROM videos WHERE share_id = ?', (share['id'],)).fetchall()
            text_content = db.execute('SELECT * FROM text_content WHERE share_id = ?', (share['id'],)).fetchall()
            return render_template('view.html', share=share, images=images, videos=videos, text_content=text_content)
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
