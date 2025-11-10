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

# Configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-key-for-testing'
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'imageshare.db')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

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
    db = get_db()
    share = db.execute('SELECT * FROM image_shares WHERE share_id = ?', (share_id,)).fetchone()
    
    if not share:
        return "Share not found", 404
    
    # If share has no password, show directly
    if not share['password_hash']:
        images = db.execute('SELECT * FROM images WHERE share_id = ?', (share['id'],)).fetchall()
        return render_template('view.html', share=share, images=images)
    
    # Check if already authenticated for this share
    if session.get(f'share_auth_{share_id}'):
        images = db.execute('SELECT * FROM images WHERE share_id = ?', (share['id'],)).fetchall()
        return render_template('view.html', share=share, images=images)
    
    if request.method == 'POST':
        password = request.form.get('password')
        
        if check_password_hash(share['password_hash'], password):
            session[f'share_auth_{share_id}'] = True
            images = db.execute('SELECT * FROM images WHERE share_id = ?', (share['id'],)).fetchall()
            return render_template('view.html', share=share, images=images)
        else:
            flash('Invalid password')
    
    return render_template('password.html', share=share)

# Initialize database before first request
@app.before_first_request
def before_first_request():
    init_db()
    print('Database initialized.')

if __name__ == '__main__':
    app.run(debug=True)
