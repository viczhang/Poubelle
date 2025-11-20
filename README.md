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

## Production Deployment

### Quick Deploy with Docker Compose

1. **Use the deployment script:**
   ```bash
   ./deploy.sh
   ```

2. **Manual deployment:**
   ```bash
   # Copy environment template
   cp .env.example .env
   
   # Edit .env with your settings (especially SECRET_KEY!)
   nano .env
   
   # Build and start
   docker-compose up -d
   ```

3. **Access the application:**
   - Application: http://localhost:5000
   - Admin panel: http://localhost:5000/admin
   - Health check: http://localhost:5000/health

### Production Features

- **Security**: Non-root user, security headers, resource limits
- **Performance**: Gunicorn WSGI server with configurable workers
- **Monitoring**: Health checks, logging, resource monitoring
- **Persistence**: Docker volumes for uploads and database
- **Scalability**: Ready for reverse proxy (Caddy, Nginx, Traefik)

### Detailed Deployment Guide

See [DEPLOYMENT.md](DEPLOYMENT.md) for:
- Complete configuration options
- Reverse proxy setup
- Backup and restore procedures
- Security best practices
- Troubleshooting guide

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-key-for-testing` | **IMPORTANT**: Set a secure random key for production |
| `ADMIN_PASSWORD` | `admin` | Admin user password |
| `SITE_TITLE` | `Poubelle` | Site title shown in UI |
| `MAX_SHARES` | `100` | Maximum number of shares allowed |
| `GUNICORN_WORKERS` | `4` | Number of worker processes |

### Docker Compose (Development)

For development, you can still use the simpler setup:

```bash
# Create an `.env` file (optional):
echo "ADMIN_PASSWORD=SuperSecure!123" > .env
echo "SITE_TITLE=MyCustomSiteName" >> .env

# Build and start:
docker compose up -d --build

# Check logs:
docker compose logs -f
```

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
