#!/usr/bin/env pwsh
# Test the Legion API

Write-Host "🧪 Testing Legion API..." -ForegroundColor Green

$baseUrl = "http://localhost:8080"

# Test health endpoint
Write-Host "📊 Testing health endpoint..." -ForegroundColor Blue
try {
    $health = Invoke-RestMethod -Uri "$baseUrl/health" -Method Get
    Write-Host "✅ Health: $($health.status)" -ForegroundColor Green
} catch {
    Write-Host "❌ Health check failed: $_" -ForegroundColor Red
    exit 1
}

# Test authentication endpoint
Write-Host "🔐 Testing authentication..." -ForegroundColor Blue
$authRequest = @{
    username = "test_user"
    password = "secure_password_with_entropy_123!"
    timestamp = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
    server_pubkey = @(1..32 | ForEach-Object { 42 })
    ip_address = "127.0.0.1"
} | ConvertTo-Json

try {
    $authResponse = Invoke-RestMethod -Uri "$baseUrl/auth" -Method Post -Body $authRequest -ContentType "application/json"
    Write-Host "✅ Authentication successful!" -ForegroundColor Green
    Write-Host "📝 Proof length: $($authResponse.proof.Length) characters" -ForegroundColor Cyan
} catch {
    Write-Host "❌ Authentication failed: $_" -ForegroundColor Red
    Write-Host "Response: $($_.Exception.Response)" -ForegroundColor Yellow
}

Write-Host "🎉 API testing complete!" -ForegroundColor Green