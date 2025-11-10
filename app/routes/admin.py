import os
import uuid
from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app.models import ImageShare, Image
from app import db

admin = Blueprint('admin', __name__)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

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
    shares = ImageShare.query.filter_by(user_id=current_user.id).all()
    return render_template('admin/dashboard.html', shares=shares, new_url=new_url)

@admin.route('/delete_all_shares', methods=['POST'])
@login_required
def delete_all_shares():
    confirm_text = request.form.get('confirm_text', '').strip().upper()
    
    if confirm_text != 'DELETE':
        flash('Confirmation text does not match. Deletion cancelled.')
        return redirect(url_for('admin.dashboard'))
    
    # Get all shares for the current user
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
@login_required
def upload():
    if request.method == 'POST':
        title = request.form.get('title')
        password = request.form.get('password')
        
        if not title:
            flash('Title is required')
            return redirect(url_for('admin.upload'))
        
        files = request.files.getlist('images')
        if not files or files[0].filename == '':
            flash('No images selected')
            return redirect(url_for('admin.upload'))
        
        share = ImageShare(title=title, user_id=current_user.id)
        share.set_password(password)
        db.session.add(share)
        db.session.flush()  # Get the ID without committing
        
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{uuid.uuid4()}_{filename}"
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                
                image = Image(
                    filename=unique_filename,
                    original_filename=filename,
                    share_id=share.id
                )
                db.session.add(image)
        
        db.session.commit()
        return redirect(url_for('admin.dashboard', new_url=url_for('share.view', share_id=share.share_id, _external=True, _scheme='https')))
    
    return render_template('admin/upload.html')

@admin.route('/manage/<int:share_id>', methods=['GET', 'POST'])
@login_required
def manage(share_id):
    share = ImageShare.query.get_or_404(share_id)
    
    if share.user_id != current_user.id:
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

        
    
    return render_template('admin/manage.html', share=share)
