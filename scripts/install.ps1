# Endpoint Behavior Monitor — Windows Installation Script
# Run as Administrator in PowerShell

$ErrorActionPreference = "Stop"

$installDir = "C:\Program Files\EBM"
$configDir = "C:\ProgramData\EBM"
$rulesDir = "$configDir\rules"
$serviceName = "EBMAgent"
$binary = "ebm-windows-amd64.exe"

Write-Host "[EBM] Installing Endpoint Behavior Monitor on Windows..."

# Create directories
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $configDir | Out-Null
New-Item -ItemType Directory -Force -Path $rulesDir | Out-Null

# Copy binary
$srcBinary = "dist\$binary"
if (Test-Path $srcBinary) {
    Copy-Item $srcBinary -Destination "$installDir\ebm.exe" -Force
} else {
    Write-Error "[EBM] Binary not found: $srcBinary. Build with: make build-windows"
    exit 1
}

# Copy config and rules
Copy-Item "config.yaml.example" -Destination "$configDir\config.yaml" -Force
Copy-Item "rules\*" -Destination $rulesDir -Recurse -Force

# Install NSSM (or use sc) for service registration
# For demo purposes we use sc directly
$exe = "$installDir\ebm.exe"
$config = "$configDir\config.yaml"

sc.exe create $serviceName binPath= "`"$exe `" -config `"$config`"`" start= auto
sc.exe description $serviceName "Endpoint Behavior Monitor Agent"

Write-Host "[EBM] Starting service..."
Start-Service -Name $serviceName

Write-Host "[EBM] Installation complete."
