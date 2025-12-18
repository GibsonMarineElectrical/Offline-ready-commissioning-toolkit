param(
  [string]$OriginRemote = "origin"
)

$ErrorActionPreference = "Stop"

function Get-RepoRoot {
  $root = (& git rev-parse --show-toplevel 2>$null)
  if (-not $root) {
    throw "Run this script from inside a git clone."
  }
  return $root.Trim()
}

function Get-OwnerRepoFromRemote([string]$remoteName) {
  $url = (& git remote get-url $remoteName).Trim()
  if (-not $url) {
    throw "Remote '$remoteName' not found."
  }

  if ($url -match 'github\.com[:/](?<owner>[^/]+)/(?<repo>[^/.]+)(?:\.git)?$') {
    return @{ Owner = $Matches.owner; Repo = $Matches.repo }
  }

  throw "Unsupported remote URL format: $url"
}

$repoRoot = Get-RepoRoot
Set-Location $repoRoot

$wikiSource = Join-Path $repoRoot "wiki"
if (-not (Test-Path $wikiSource)) {
  throw "Missing 'wiki/' folder at repo root."
}

$ownerRepo = Get-OwnerRepoFromRemote -remoteName $OriginRemote
$wikiRemote = "https://github.com/$($ownerRepo.Owner)/$($ownerRepo.Repo).wiki.git"

$tempDir = Join-Path $env:TEMP ("wiki-" + [guid]::NewGuid().ToString("n"))

try {
  Write-Host "Cloning wiki repo:" $wikiRemote
  & git clone $wikiRemote $tempDir
} catch {
  Write-Host ""
  Write-Host "Wiki repo not initialised yet."
  Write-Host "Create the first wiki page in GitHub (Repo -> Wiki -> Create the first page)."
  Write-Host "Re-run this script after saving the first page."
  exit 1
}

try {
  Get-ChildItem -Path $tempDir -File -Filter "*.md" | Remove-Item -Force
  Copy-Item -Path (Join-Path $wikiSource "*.md") -Destination $tempDir -Force

  Set-Location $tempDir
  & git add -A

  & git diff --cached --quiet
  if ($LASTEXITCODE -eq 0) {
    Write-Host "Wiki is already up to date."
    exit 0
  }

  & git commit -m "Update wiki"
  & git push
  Write-Host "Wiki published."
} finally {
  Set-Location $repoRoot
  if (Test-Path $tempDir) {
    Remove-Item -Recurse -Force $tempDir
  }
}

