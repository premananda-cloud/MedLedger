#!/bin/bash
# MedLedger Complete Setup Script

set -e

echo "🚀 Starting MedLedger Docker Setup..."
echo "======================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Check if .env exists, if not create from .env.docker
if [ ! -f .env ]; then
    echo "📝 Creating .env file from .env.docker..."
    cp .env.docker .env
    echo "✅ .env file created"
else
    echo "ℹ️  .env file already exists, using existing configuration"
fi

# Check if SQL schema exists
if [ ! -f sql/V1__medledger_schema.sql ]; then
    echo "❌ SQL schema file not found at sql/V1__medledger_schema.sql"
    echo "Please ensure your schema file is in the correct location."
    exit 1
else
    echo "✅ SQL schema found: sql/V1__medledger_schema.sql"
fi

echo ""
echo "📦 Building and starting Docker containers..."
echo "This may take a few minutes on first run..."

# Build and start containers
docker-compose up -d --build

echo ""
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check if services are running
if docker-compose ps | grep -q "Up"; then
    echo ""
    echo "✅ MedLedger is now running!"
    echo "======================================"
    echo "📍 API URL: http://localhost:8000"
    echo "📍 API Documentation: http://localhost:8000/docs"
    echo "📍 ReDoc: http://localhost:8000/redoc"
    echo "📍 Database: localhost:5432"
    echo ""
    echo "📊 Service Status:"
    docker-compose ps
    echo ""
    echo "📝 To view logs: docker-compose logs -f"
    echo "🛑 To stop: docker-compose down"
    echo "🧹 To clean: docker-compose down -v"
else
    echo "❌ Something went wrong. Check logs with: docker-compose logs"
    exit 1
fi
