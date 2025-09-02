#!/bin/bash
set -euo pipefail

echo "🚀 Deploying Legion ZK Authentication System"

# Check prerequisites
command -v docker >/dev/null 2>&1 || { echo "❌ Docker required"; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "❌ Docker Compose required"; exit 1; }

# Environment setup
if [ ! -f .env ]; then
    echo "📝 Creating .env from template"
    cp .env.example .env
    echo "⚠️  Please edit .env with your configuration"
    exit 1
fi

# Build and deploy
echo "🔨 Building containers..."
docker-compose build

echo "🚀 Starting services..."
docker-compose up -d

# Wait for health check
echo "⏳ Waiting for service to be ready..."
for i in {1..30}; do
    if curl -f http://localhost:8080/health >/dev/null 2>&1; then
        echo "✅ Legion server is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ Service failed to start"
        docker-compose logs
        exit 1
    fi
    sleep 2
done

echo "🎉 Deployment complete!"
echo "📊 Health: http://localhost:8080/health"
echo "📚 API: http://localhost:8080/auth"