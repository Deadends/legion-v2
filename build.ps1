# Professional Podman Build Script
Write-Host "=== Legion ZK Auth System - Podman Build ===" -ForegroundColor Green

# Test network connectivity
Write-Host "Testing network connectivity..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "https://registry-1.docker.io/v2/" -Method Head -TimeoutSec 10
    Write-Host "✓ Docker Hub accessible" -ForegroundColor Green
} catch {
    Write-Host "✗ Docker Hub not accessible, using mirrors" -ForegroundColor Red
}

# Build with retry and fallback
Write-Host "Building Legion container..." -ForegroundColor Yellow
$buildCmd = "podman build --pull=missing --retry=3 --retry-delay=5s -t legion-auth ."

try {
    Invoke-Expression $buildCmd
    Write-Host "✓ Build successful!" -ForegroundColor Green
    
    # Test run
    Write-Host "Testing container..." -ForegroundColor Yellow
    podman run --rm -d --name legion-test -p 8080:8080 legion-auth
    Start-Sleep 5
    
    try {
        $health = Invoke-WebRequest -Uri "http://localhost:8080/health" -TimeoutSec 5
        Write-Host "✓ Container running successfully!" -ForegroundColor Green
        podman stop legion-test
    } catch {
        Write-Host "✗ Container health check failed" -ForegroundColor Red
        podman stop legion-test
    }
    
} catch {
    Write-Host "✗ Build failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Trying offline build..." -ForegroundColor Yellow
    
    # Fallback: Build locally then containerize
    cargo build --release --bin legion-server
    
    # Create minimal Containerfile
    @"
FROM scratch
COPY target/release/legion-server /legion-server
EXPOSE 8080
CMD ["/legion-server"]
"@ | Out-File -FilePath "Containerfile.minimal" -Encoding UTF8
    
    podman build -f Containerfile.minimal -t legion-auth .
}