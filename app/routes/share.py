from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from app.models import ImageShare, AccessLog
from app import db

share = Blueprint('share', __name__)

@share.route('/s/<share_id>', methods=['GET', 'POST'])
def view(share_id):
    share = ImageShare.query.filter_by(share_id=share_id).first_or_404()
    
    # Get images and videos separately
    images = share.images.filter_by(file_type='image').all()
    videos = share.images.filter_by(file_type='video').all()
    
    # No password set: show directly
    if not share.password_hash:
        # Create access log
        # request.remote_addr will return the real client IP when ProxyFix is properly configured
        log = AccessLog(
            share_id=share.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(log)
        db.session.commit()
        return render_template('share/view.html', share=share, images=images, videos=videos)
    
    # Check if already authenticated for this share
    if session.get(f'share_auth_{share_id}'):
        # Create access log
        # request.remote_addr will return the real client IP when ProxyFix is properly configured
        log = AccessLog(
            share_id=share.id,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(log)
        db.session.commit()
        return render_template('share/view.html', share=share, images=images, videos=videos)
    
    if request.method == 'POST':
        password = request.form.get('password')
        
        if share.check_password(password):
            # Create access log
            # request.remote_addr will return the real client IP when ProxyFix is properly configured
            log = AccessLog(
                share_id=share.id,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            db.session.add(log)
            db.session.commit()
            
            session[f'share_auth_{share_id}'] = True
            return render_template('share/view.html', share=share, images=images, videos=videos)
        else:
            flash('Invalid password')
    
    return render_template('share/password.html', share=share)
