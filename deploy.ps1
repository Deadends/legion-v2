#!/usr/bin/env pwsh
# Legion Production Deployment Script for Windows

Write-Host "🚀 Deploying Legion ZK Authentication System" -ForegroundColor Green

# Check prerequisites
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Docker required. Please install Docker Desktop" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Docker Compose required" -ForegroundColor Red
    exit 1
}

# Environment setup
if (-not (Test-Path ".env")) {
    Write-Host "📝 Creating .env from template" -ForegroundColor Yellow
    Copy-Item ".env.example" ".env"
    Write-Host "⚠️  Please edit .env with your configuration" -ForegroundColor Yellow
    Write-Host "Then run this script again" -ForegroundColor Yellow
    exit 1
}

# Build and test first
Write-Host "🔨 Building Rust project..." -ForegroundColor Blue
cargo build --release --bin legion-server
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Build failed" -ForegroundColor Red
    exit 1
}

Write-Host "🧪 Running tests..." -ForegroundColor Blue
cargo test
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Tests failed" -ForegroundColor Red
    exit 1
}

# Docker deployment
Write-Host "🔨 Building containers..." -ForegroundColor Blue
docker-compose build
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Container build failed" -ForegroundColor Red
    exit 1
}

Write-Host "🚀 Starting services..." -ForegroundColor Blue
docker-compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Service start failed" -ForegroundColor Red
    exit 1
}

# Wait for health check
Write-Host "⏳ Waiting for service to be ready..." -ForegroundColor Blue
$maxAttempts = 30

for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    Start-Sleep -Seconds 2
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8080/health" -UseBasicParsing -TimeoutSec 5
        if ($response.StatusCode -eq 200) {
            Write-Host "✅ Legion server is ready!" -ForegroundColor Green
            break
        }
    }
    catch {
        if ($attempt -eq $maxAttempts) {
            Write-Host "❌ Service failed to start after $maxAttempts attempts" -ForegroundColor Red
            Write-Host "📋 Container logs:" -ForegroundColor Yellow
            docker-compose logs
            exit 1
        }
    }
}

Write-Host "🎉 Deployment complete!" -ForegroundColor Green
Write-Host "📊 Health: http://localhost:8080/health" -ForegroundColor Cyan
Write-Host "📚 API: http://localhost:8080/auth" -ForegroundColor Cyan
Write-Host "🐳 View logs: docker-compose logs -f" -ForegroundColor Cyan
Write-Host "🛑 Stop: docker-compose down" -ForegroundColor Cyan