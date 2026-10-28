import os
from sqlalchemy import inspect, text
from app import create_app, db
from app.models import User

# This script needs to run within the Flask application context.
# Create a dummy app instance to get the context.
app = create_app()

with app.app_context():
    # Create all database tables
    db.create_all()

    # Ensure newer columns exist when migrating an older SQLite database
    inspector = inspect(db.engine)
    if 'image_share' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('image_share')]
        if 'text_content' not in columns:
            db.session.execute(text('ALTER TABLE image_share ADD COLUMN text_content TEXT'))
            db.session.commit()

    if 'image' in inspector.get_table_names():
        columns = [col['name'] for col in inspector.get_columns('image')]
        if 'file_type' not in columns:
            db.session.execute(text("ALTER TABLE image ADD COLUMN file_type VARCHAR(20) DEFAULT 'image'"))
            db.session.commit()

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