import os
from app import create_app, db
from app.models import User

# This script needs to run within the Flask application context.
# Create a dummy app instance to get the context.
app = create_app()

with app.app_context():
    # Create all database tables
    db.create_all()

    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin')
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin')
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()
        print("Admin user created.")
    else:
        print("Admin user already exists.")

print("Database initialized and admin user checked.")