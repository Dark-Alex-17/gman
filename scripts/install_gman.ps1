<#
gman installer (Windows/PowerShell 5+ and PowerShell 7)

Examples:
  powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb https://raw.githubusercontent.com/Dark-Alex-17/gman/main/scripts/install_gman.ps1 | iex"
  pwsh -c "irm https://raw.githubusercontent.com/Dark-Alex-17/gman/main/scripts/install_gman.ps1 | iex -Version vX.Y.Z"

Parameters:
  -Version   <tag>         (default: latest)
  -BinDir    <path>        (default: %LOCALAPPDATA%\gman\bin on Windows; ~/.local/bin on *nix PowerShell)
#>

[CmdletBinding()]
param(
  [string]$Version = $env:GMAN_VERSION,
  [string]$BinDir = $env:BIN_DIR
)

$Repo = 'Dark-Alex-17/gman'

function Write-Info($msg) { Write-Host "[gman-install] $msg" }
function Fail($msg) { Write-Error $msg; exit 1 }

Add-Type -AssemblyName System.Runtime
$isWin = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)
$isMac = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::OSX)
$isLin = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)

if ($isWin) { $os = 'windows' }
elseif ($isMac) { $os = 'darwin' }
elseif ($isLin) { $os = 'linux' }
else { Fail "Unsupported OS" }

switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
  'X64'  { $arch = 'x86_64' }
  'Arm64'{ $arch = 'aarch64' }
  default { Fail "Unsupported arch: $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)" }
}

if (-not $BinDir) {
  if ($isWin) { $BinDir = Join-Path $env:LOCALAPPDATA 'gman\bin' }
  else { $userHome = $env:HOME; if (-not $userHome) { $userHome = (Get-Item -Path ~).FullName }; $BinDir = Join-Path $userHome '.local/bin' }
}
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

Write-Info "Target: $os-$arch"

$dlBase = if ($Version) { "https://github.com/$Repo/releases/download/$Version" } else { "https://github.com/$Repo/releases/latest/download" }

$candidates = @()
if ($os -eq 'windows') {
  if ($arch -eq 'x86_64') { $candidates += 'gman-x86_64-pc-windows-msvc.zip' }
  else { $candidates += 'gman-aarch64-pc-windows-msvc.zip' }
} elseif ($os -eq 'darwin') {
  if ($arch -eq 'x86_64') { $candidates += 'gman-x86_64-apple-darwin.tar.gz' }
  else { $candidates += 'gman-aarch64-apple-darwin.tar.gz' }
} elseif ($os -eq 'linux') {
  if ($arch -eq 'x86_64') {
    $candidates += 'gman-x86_64-unknown-linux-musl.tar.gz'
    $candidates += 'gman-x86_64-unknown-linux-gnu.tar.gz'
  } else {
    $candidates += 'gman-aarch64-unknown-linux-musl.tar.gz'
  }
} else {
  Fail "Unsupported OS for this installer: $os"
}

$tmp = New-Item -ItemType Directory -Force -Path ([IO.Path]::Combine([IO.Path]::GetTempPath(), "gman-$(Get-Random)"))
$archive = Join-Path $tmp.FullName 'asset'

$assetName = $null; $assetUrl = $null
foreach ($c in $candidates) {
  $url = "$dlBase/$c"
  Write-Info "Trying $url"
  try {
    Invoke-WebRequest -UseBasicParsing -Headers @{ 'User-Agent' = 'gman-installer' } -Uri $url -OutFile $archive -ErrorAction Stop
    $assetName = $c; $assetUrl = $url
    break
  } catch { continue }
}
if (-not $assetName) {
  $verLabel = if ($Version) { $Version } else { 'latest' }
  Write-Error "No matching asset found for $os-$arch (version: $verLabel). Tried:"; $candidates | ForEach-Object { Write-Error "  - $_" }
  exit 1
}

Write-Info "Selected asset: $assetName"
Write-Info "Download URL:  $assetUrl"

$extractDir = Join-Path $tmp.FullName 'extract'; New-Item -ItemType Directory -Force -Path $extractDir | Out-Null

if ($assetName -match '\.zip$') {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [System.IO.Compression.ZipFile]::ExtractToDirectory($archive, $extractDir)
} elseif ($assetName -match '\.tar\.gz$' -or $assetName -match '\.tgz$') {
  $tar = Get-Command tar -ErrorAction SilentlyContinue
  if ($tar) { & $tar.Source -xzf $archive -C $extractDir }
  else { Fail "Asset is tar archive but 'tar' is not available." }
} else {
  try { Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory($archive, $extractDir) }
  catch {
    $tar = Get-Command tar -ErrorAction SilentlyContinue
    if ($tar) { & $tar.Source -xf $archive -C $extractDir } else { Fail "Unknown archive format; neither zip nor tar workable." }
  }
}

$bin = $null
Get-ChildItem -Recurse -File $extractDir | ForEach-Object {
  if ($isWin) { if ($_.Name -ieq 'gman.exe') { $bin = $_.FullName } }
  else { if ($_.Name -ieq 'gman') { $bin = $_.FullName } }
}
if (-not $bin) { Fail "Could not find gman binary inside the archive." }

if (-not $isWin) { try { & chmod +x -- $bin } catch {} }

$exec = if ($isWin) { 'gman.exe'} else { 'gman' }
$dest = Join-Path $BinDir $exec
Copy-Item -Force $bin $dest
Write-Info "Installed: $dest"

if ($isWin) {
  $pathParts = ($env:Path -split ';') | Where-Object { $_ -ne '' }
  if ($pathParts -notcontains $BinDir) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User'); if (-not $userPath) { $userPath = '' }
    if (-not ($userPath -split ';' | Where-Object { $_ -eq $BinDir })) {
      $newUserPath = if ($userPath.Trim().Length -gt 0) { "$userPath;$BinDir" } else { $BinDir }
      [Environment]::SetEnvironmentVariable('Path', $newUserPath, 'User')
      Write-Info "Added to User PATH: $BinDir (restart shell to take effect)"
    }
  }
} else {
  if (-not ($env:PATH -split ':' | Where-Object { $_ -eq $BinDir })) {
    Write-Info "Note: $BinDir is not in PATH. Add it to your shell profile."
  }
}

Write-Info "Done. Try: gman --help"

