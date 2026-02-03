# Get the directory where this script is located
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set the output directory relative to script location
$OutputDir = Join-Path $ScriptDir "../../.scripts/"

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    Write-Host "Created output directory: $OutputDir" -ForegroundColor Green
}

# Resolve to absolute path
$OutputDir = Resolve-Path $OutputDir

# Set the output binary name
$OutputBinary = Join-Path $OutputDir "doh_lookup"

Write-Host "Building for Linux..." -ForegroundColor Cyan
Write-Host "Output: $OutputBinary" -ForegroundColor Yellow

# Set environment variables for cross-compilation
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"

# Build the Go application
go build -buildvcs=false -o $OutputBinary

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build successful!" -ForegroundColor Green
    Write-Host "Binary location: $OutputBinary" -ForegroundColor Green

    # Display file info
    $fileInfo = Get-Item $OutputBinary
    Write-Host "Size: $([math]::Round($fileInfo.Length / 1MB, 2)) MB" -ForegroundColor Gray
} else {
    Write-Host "Build failed with exit code $LASTEXITCODE" -ForegroundColor Red
    exit $LASTEXITCODE
}
