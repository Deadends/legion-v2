# Quick local development run

Write-Host "Starting Legion locally..." -ForegroundColor Green

# Set environment variables
$env:RUST_LOG = "info"
$env:LEGION_SECURITY_LEVEL = "Production"
$env:LEGION_MAX_CONCURRENT = "1000"

# Build and run
Write-Host "Building..." -ForegroundColor Blue
cargo build --release --bin legion-server

if ($LASTEXITCODE -eq 0) {
    Write-Host "Starting server on http://localhost:8080" -ForegroundColor Green
    cargo run --bin legion-server
} else {
    Write-Host "Build failed" -ForegroundColor Red
    exit 1
}