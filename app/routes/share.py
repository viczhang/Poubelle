from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from app.models import ImageShare

share = Blueprint('share', __name__)

@share.route('/s/<share_id>', methods=['GET', 'POST'])
def view(share_id):
    share = ImageShare.query.filter_by(share_id=share_id).first_or_404()
    
    # No password set: show directly
    if not share.password_hash:
        return render_template('share/view.html', share=share)
    
    # Check if already authenticated for this share
    if session.get(f'share_auth_{share_id}'):
        return render_template('share/view.html', share=share)
    
    if request.method == 'POST':
        password = request.form.get('password')
        
        if share.check_password(password):
            session[f'share_auth_{share_id}'] = True
            return render_template('share/view.html', share=share)
        else:
            flash('Invalid password')
    
    return render_template('share/password.html', share=share)
