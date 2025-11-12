# Poubelle

A simple web application for securely sharing images with password protection.

## Features

- Password-protected admin area
- Upload multiple images at once
- Set custom passwords for each image share
- Generate unique short URLs (3 characters) for sharing
- Access logs for each share (date, time, IP, user agent)
- Manage uploaded images and shares
- Minimal and clean shared image viewing page

## Setup

1. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

2. Run the application:
   ```
   python run.py
   ```

3. Access the admin area:
   - URL: http://localhost:5000/login
   - Default credentials: 
     - Username: `admin`
     - Password: `admin`

## Usage

1. Log in to the admin area
2. Upload images and set a password
3. Share the generated URL with friends
4. Friends can view images by entering the password

## Security Note

## Docker Compose Deployment

Use Docker Compose to run the app on your server:

1. Create an `.env` file next to `docker-compose.yml` (optional but recommended):
   ```bash
   echo "ADMIN_PASSWORD=SuperSecure!123" > .env
   echo "SITE_TITLE=MyCustomSiteName" >> .env
   ```

2. Review `docker-compose.yml`:
   - The file already includes environment variables with default values:
     - `ADMIN_PASSWORD`: Defaults to 'admin' if not set
     - `SITE_TITLE`: Defaults to 'Poubelle' if not set

3. You can customize these variables directly in the `.env` file or by setting environment variables when running Docker Compose:
   ```bash
   SITE_TITLE="MyCustomGallery" docker-compose up -d
   ```

4. When deployed, the site will use the custom title set in your environment variables.
   - The service exposes `5000` on the host
   - Persists data via volumes:
     - `./static/uploads:/app/static/uploads`
     - `./imageshare.db:/app/imageshare.db`
   - Supports admin password via environment:
     ```yaml
     environment:
       FLASK_ENV: production
       ADMIN_PASSWORD: ${ADMIN_PASSWORD:-admin}
     command: python run.py
     ```

3. Build and start:
   ```bash
   docker compose up -d --build
   ```

4. Check logs and status:
   ```bash
   docker compose logs -f
   docker compose ps
   ```

5. Access the app:
   - `http://<your-server-ip>:5000` or your domain if reverse-proxied

6. Stop or update:
   ```bash
   docker compose down
   docker compose pull && docker compose up -d
   ```

### Notes
- The container’s default admin credentials are `admin` / `admin` unless `ADMIN_PASSWORD` is set.
- The container now uses `run.py` (SQLAlchemy app) by default for persistence and avoids `app.py`’s reinitialization behavior.

## Environment Variables

- `ADMIN_PASSWORD`: Sets the initial admin password at app startup when the admin user is created.
  - Default: `admin`
  - Example (Linux/macOS):
    ```bash
    export ADMIN_PASSWORD="SuperSecure!123"
    python run.py
    ```

- `SECRET_KEY`: Flask secret key used for sessions.
  - Default: development key
  - Set a strong value in production.

**Data Initialization**
- In `app.py`, the database is reinitialized on first request, which recreates the admin user using `ADMIN_PASSWORD`. Use `run.py` (SQLAlchemy app) to avoid dropping data, or remove the reinitialization logic in `app.py` for production.
