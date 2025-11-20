# Poubelle Deployment Guide

## Production Deployment with Docker

### Prerequisites
- Docker and Docker Compose installed
- Domain name configured (optional)
- Reverse proxy (Caddy, Nginx, or Traefik) configured (optional)

### Quick Start

1. **Clone and prepare the repository:**
   ```bash
   git clone <your-repo-url>
   cd poubelle
   ```

2. **Set up environment variables:**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Build and run with Docker Compose:**
   ```bash
   docker-compose up -d
   ```

4. **Access the application:**
   - Default: http://localhost:5000
   - Admin panel: http://localhost:5000/admin
   - Default admin credentials: admin / (set in ADMIN_PASSWORD env var)

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `dev-key-for-testing` | **IMPORTANT**: Set a secure random key for production |
| `ADMIN_PASSWORD` | `admin` | Admin user password |
| `SITE_TITLE` | `Poubelle` | Site title shown in UI |
| `MAX_SHARES` | `100` | Maximum number of shares allowed |
| `GUNICORN_WORKERS` | `4` | Number of worker processes |
| `GUNICORN_TIMEOUT` | `120` | Worker timeout in seconds |

### Production Considerations

#### Security
- **Change the SECRET_KEY** to a secure random value
- **Use strong admin passwords**
- **Configure HTTPS** with your reverse proxy
- **Set up firewall rules** to restrict access
- **Regular backups** of uploads and database

#### Performance
- Adjust `GUNICORN_WORKERS` based on your server's CPU cores
- Monitor memory usage and adjust limits accordingly
- Consider using external database for larger deployments
- Set up CDN for static files

#### Storage
- Uploads are stored in Docker volume `poubelle_uploads`
- Database is stored in Docker volume `poubelle_db`
- Both volumes are persistent across container restarts

### Backup and Restore

#### Backup
```bash
# Backup uploads
docker run --rm -v poubelle_uploads:/data -v $(pwd):/backup alpine tar czf /backup/uploads-backup.tar.gz -C /data .

# Backup database
docker run --rm -v poubelle_db:/data -v $(pwd):/backup alpine tar czf /backup/db-backup.tar.gz -C /data .
```

#### Restore
```bash
# Restore uploads
docker run --rm -v poubelle_uploads:/data -v $(pwd):/backup alpine tar xzf /backup/uploads-backup.tar.gz -C /data

# Restore database
docker run --rm -v poubelle_db:/data -v $(pwd):/backup alpine tar xzf /backup/db-backup.tar.gz -C /data
```

### Monitoring

The application includes:
- Health check endpoint: `/health`
- Access logging via Docker
- Resource usage monitoring via Docker stats

### Troubleshooting

#### Check logs
```bash
docker-compose logs -f poubelle
```

#### Check health
```bash
curl http://localhost:5000/health
```

#### Restart service
```bash
docker-compose restart poubelle
```

### Reverse Proxy Configuration

#### Caddy (recommended)
```
yourdomain.com {
    reverse_proxy poubelle:5000
    encode gzip
    
    # Security headers
    header {
        X-Frame-Options DENY
        X-Content-Type-Options nosniff
        X-XSS-Protection "1; mode=block"
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
    }
}
```

#### Nginx
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://poubelle:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Updates

To update the application:
```bash
# Pull latest changes
git pull origin main

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Support

For issues and questions, please check:
1. Application logs: `docker-compose logs`
2. Health endpoint: `curl http://localhost:5000/health`
3. Docker container status: `docker-compose ps`