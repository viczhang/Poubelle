#!/bin/bash
# Poubelle Deployment Script

set -e

echo "🚀 Starting Poubelle deployment..."

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from .env.example..."
    cp .env.example .env
    echo "📝 Please edit .env file with your configuration before continuing."
    echo "   Especially change SECRET_KEY to a secure random value!"
    read -p "Press Enter to continue after editing .env..."
fi

# Build the Docker image
echo "🔨 Building Docker image..."
docker-compose build --no-cache

# Stop existing containers if running
echo "🛑 Stopping existing containers..."
docker-compose down || true

# Start the application
echo "🚀 Starting application..."
docker-compose up -d

# Wait for the application to start
echo "⏳ Waiting for application to start..."
sleep 10

# Health check
echo "🏥 Performing health check..."
if curl -f http://localhost:5000/health > /dev/null 2>&1; then
    echo "✅ Application is healthy!"
else
    echo "❌ Health check failed. Check logs with: docker-compose logs"
    exit 1
fi

# Show status
echo "📊 Application status:"
docker-compose ps

echo ""
echo "🎉 Deployment complete!"
echo ""
echo "Application is running at: http://localhost:5000"
echo "Admin panel: http://localhost:5000/admin"
echo ""
echo "Useful commands:"
echo "  View logs: docker-compose logs -f"
echo "  Stop app: docker-compose down"
echo "  Restart: docker-compose restart"
echo "  Update: ./deploy.sh"