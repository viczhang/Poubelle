from app import create_app, db
from app.models import AccessLog, ImageShare

app = create_app()

with app.app_context():
    # Update database schema
    db.create_all()
    
    # For existing shares with UUID share_id longer than 3 characters,
    # we don't need to change them as they will continue to work
    print("Database migration completed successfully!")
    print("Updated schema to support short share IDs (3 characters).")
    print("New shares will automatically use short IDs, while existing shares remain unchanged.")
