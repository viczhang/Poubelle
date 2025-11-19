import os
import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app.models import ImageShare, Image
from app import db

admin = Blueprint('admin', __name__)

def allowed_file(filename, file_type='image'):
    """Check if file extension is allowed based on file type."""
    if '.' not in filename:
        return False
    
    ext = filename.rsplit('.', 1)[1].lower()
    
    if file_type == 'image':
        return ext in {'png', 'jpg', 'jpeg', 'gif'}
    elif file_type == 'video':
        return ext in {'mp4', 'webm', 'avi', 'mov'}
    elif file_type == 'text':
        return ext in {'txt', 'md', 'json', 'xml', 'csv'}
    
    return False

@admin.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
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
                current_user.set_password(new_password)
                db.session.commit()
                flash('Admin password updated successfully')
        return redirect(url_for('admin.dashboard'))

    new_url = request.args.get('new_url')
    # For admin users, show all shares ordered by creation date (newest first)
    shares = ImageShare.query.order_by(ImageShare.created_at.desc()).all()
    return render_template('admin/dashboard.html', shares=shares, new_url=new_url, is_admin=True)

@admin.route('/delete_all_shares', methods=['POST'])
@login_required
def delete_all_shares():
    confirm_text = request.form.get('confirm_text', '').strip().upper()
    
    if confirm_text != 'DELETE':
        flash('Confirmation text does not match. Deletion cancelled.')
        return redirect(url_for('admin.dashboard'))
    
    # Admin users can delete all shares, regular users can only delete their own shares
    if current_user.username == 'admin':
        shares = ImageShare.query.all()
    else:
        shares = ImageShare.query.filter_by(user_id=current_user.id).all()
    
    if not shares:
        flash('No shares to delete.')
        return redirect(url_for('admin.dashboard'))
    
    try:
        # Delete all associated images and their files
        for share in shares:
            for image in share.images:
                # Delete the image file if it exists
                image_path = os.path.join(current_app.config['UPLOAD_FOLDER'], image.filename)
                if os.path.exists(image_path):
                    os.remove(image_path)
                # Delete the image record
                db.session.delete(image)
            # Delete the share record
            db.session.delete(share)
        
        db.session.commit()
        flash('All shares have been successfully deleted.')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting shares: {str(e)}')
    
    return redirect(url_for('admin.dashboard'))

@admin.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        title = request.form.get('title')
        password = request.form.get('password')
        text_content = request.form.get('text_content', '').strip()
        
        if not title:
            flash('Title is required')
            return redirect(url_for('admin.upload'))
        
        # Get files from different input types
        image_files = request.files.getlist('image_files[]')
        video_files = request.files.getlist('video_files[]')
        
        # Filter out empty files
        image_files = [f for f in image_files if f and f.filename]
        video_files = [f for f in video_files if f and f.filename]
        
        # Validate content requirements
        if not image_files and not video_files and not text_content:
            flash('Please provide at least one type of content (images, videos, or text)')
            return redirect(url_for('admin.upload'))
        
        # Validate file limits
        if len(image_files) > 10:
            flash('Maximum 10 images allowed per share')
            return redirect(url_for('admin.upload'))
        
        if len(video_files) > 10:
            flash('Maximum 10 videos allowed per share')
            return redirect(url_for('admin.upload'))
        
        # Validate file sizes and types
        for file in image_files:
            if file and allowed_file(file.filename, 'image'):
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                if file_size > 5 * 1024 * 1024:  # 5MB limit
                    flash(f'Image {file.filename} exceeds 5MB limit')
                    return redirect(url_for('admin.upload'))
        
        for file in video_files:
            if file and allowed_file(file.filename, 'video'):
                file.seek(0, os.SEEK_END)
                file_size = file.tell()
                file.seek(0)
                if file_size > 10 * 1024 * 1024:  # 10MB limit
                    flash(f'Video {file.filename} exceeds 10MB limit')
                    return redirect(url_for('admin.upload'))
        
        # Create share with text content if provided
        user_id = current_user.id if current_user.is_authenticated else None
        share = ImageShare(title=title, user_id=user_id)
        if text_content:
            share.text_content = text_content
        share.set_password(password)
        db.session.add(share)
        db.session.flush()
        
        # Process image files
        for file in image_files:
            if file and allowed_file(file.filename, 'image'):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                
                image = Image(
                    filename=unique_filename,
                    original_filename=filename,
                    share_id=share.id,
                    file_type='image'
                )
                db.session.add(image)
        
        # Process video files
        for file in video_files:
            if file and allowed_file(file.filename, 'video'):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                
                video = Image(
                    filename=unique_filename,
                    original_filename=filename,
                    share_id=share.id,
                    file_type='video'
                )
                db.session.add(video)
        
        db.session.commit()
        share_url = url_for('share.view', share_id=share.share_id, _external=True, _scheme='https')
        
        # For logged in users, redirect to dashboard with the new URL
        if current_user.is_authenticated:
            return redirect(url_for('admin.dashboard', new_url=share_url))
        else:
            # For non-logged in users, show a simple success page with just the URL
            return render_template('admin/upload_success.html', new_url=share_url)
    
    return render_template('admin/upload.html')

@admin.route('/manage/<int:share_id>', methods=['GET', 'POST'])
@login_required
def manage(share_id):
    from app.models import AccessLog
    
    share = ImageShare.query.get_or_404(share_id)
    
    # Admin users can manage all shares, regular users can only manage their own shares
    # Default admin username is assumed to be 'admin'
    if share.user_id != current_user.id and current_user.username != 'admin':
        flash('You do not have permission to manage this share')
        return redirect(url_for('admin.dashboard'))
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update':
            title = request.form.get('title')
            password = request.form.get('password')
            
            if title:
                share.title = title
            if password:
                share.set_password(password)
            
            db.session.commit()
            flash('Share updated successfully')
        
        elif action == 'delete':
            # Delete associated images from filesystem
            for image in share.images:
                try:
                    os.remove(os.path.join(current_app.config['UPLOAD_FOLDER'], image.filename))
                except:
                    pass
            
            db.session.delete(share)
            db.session.commit()
            flash('Share deleted successfully')
            return redirect(url_for('admin.dashboard'))
        
        elif action == 'delete_image':
            image_id = request.form.get('image_id')
            image = Image.query.get(image_id)
            
            if image and image.share_id == share.id:
                try:
                    os.remove(os.path.join(current_app.config['UPLOAD_FOLDER'], image.filename))
                except:
                    pass
                
                db.session.delete(image)
                db.session.commit()
            flash('Image deleted successfully')

    
    return render_template('admin/manage.html', share=share, AccessLog=AccessLog)
