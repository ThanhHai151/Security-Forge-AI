<#
.SYNOPSIS
  SecForge installer for Windows (native PowerShell).

.DESCRIPTION
  Clones SecForge, creates an isolated Python venv, builds the Web UI (if Node is
  present), and puts a `secforge` command on your PATH. Re-running updates in place.

  One-liner:
      iex (irm https://<myrepogithub>/install.ps1)

  Override defaults with env vars before running:
      $env:SECFORGE_REPO   = 'https://github.com/you/secforge.git'
      $env:SECFORGE_BRANCH = 'main'
#>
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'

# ── Config (override via env) ────────────────────────────────────────────────
$RepoUrl    = if ($env:SECFORGE_REPO)   { $env:SECFORGE_REPO }   else { 'https://github.com/<myrepogithub>/secforge.git' }
$Branch     = if ($env:SECFORGE_BRANCH) { $env:SECFORGE_BRANCH } else { 'main' }
$InstallDir = if ($env:SECFORGE_HOME)   { $env:SECFORGE_HOME }   else { Join-Path $env:USERPROFILE '.secforge' }
$BinDir     = Join-Path $InstallDir 'bin'

# ── Pretty output ────────────────────────────────────────────────────────────
function Info($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "[x] $m" -ForegroundColor Red; exit 1 }
function Have($cmd) { [bool](Get-Command $cmd -ErrorAction SilentlyContinue) }

# ── Resolve a Python >= 3.11 interpreter ─────────────────────────────────────
# Sets $script:PyExe (executable) and $script:PyPre (prefix args, e.g. @('-3') for the
# `py` launcher). Invoke as:  & $script:PyExe @($script:PyPre + @('-m','venv',...))
function Find-Python {
    foreach ($cand in @('python', 'python3', 'py')) {
        if (-not (Have $cand)) { continue }
        $pre = if ($cand -eq 'py') { @('-3') } else { @() }
        try {
            $ver = & $cand @($pre + @('-c', 'import sys;print("%d.%d"%sys.version_info[:2])')) 2>$null
            if ($ver -match '^3\.(\d+)$' -and [int]$Matches[1] -ge 11) {
                $script:PyExe = $cand
                $script:PyPre = $pre
                return $true
            }
        } catch { }
    }
    return $false
}

function Ensure-Prereqs {
    if (-not (Have 'git')) {
        if (Have 'winget') { Info 'Installing Git via winget…'; winget install --id Git.Git -e --source winget --accept-package-agreements --accept-source-agreements }
        else { Die 'git is required. Install Git for Windows: https://git-scm.com/download/win' }
    }
    if (-not (Find-Python)) {
        if (Have 'winget') {
            Info 'Installing Python via winget…'
            winget install --id Python.Python.3.12 -e --source winget --accept-package-agreements --accept-source-agreements
            $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
        }
        if (-not (Find-Python)) { Die 'Python >= 3.11 is required. Install it (https://python.org) and re-run.' }
    }
    Info "Python: $script:PyExe $($script:PyPre -join ' ')"
    if (-not (Have 'npm')) {
        Warn 'Node/npm not found — the Web UI build will be skipped (the Terminal UI still works).'
        if (Have 'winget') {
            Info 'Attempting to install Node LTS via winget…'
            try { winget install --id OpenJS.NodeJS.LTS -e --source winget --accept-package-agreements --accept-source-agreements } catch { Warn 'Node install failed; continuing without the Web UI.' }
            $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
        }
    }
}

# ── Clone or update the repo ─────────────────────────────────────────────────
function Fetch-Repo {
    if (Test-Path (Join-Path $InstallDir '.git')) {
        Info "Updating existing checkout in $InstallDir"
        git -C $InstallDir fetch --depth 1 origin $Branch
        git -C $InstallDir reset --hard "origin/$Branch"
    } else {
        Info "Cloning $RepoUrl -> $InstallDir"
        git clone --depth 1 --branch $Branch $RepoUrl $InstallDir
    }
}

# ── Python venv + package install ────────────────────────────────────────────
function Setup-Python {
    Info "Creating virtualenv at $InstallDir\.venv"
    $pyParts = $script:Py.Split(' ')
    & $pyParts[0] @($pyParts[1..($pyParts.Length-1)] + @('-m','venv',(Join-Path $InstallDir '.venv')))
    $venvPy = Join-Path $InstallDir '.venv\Scripts\python.exe'
    & $venvPy -m pip install --quiet --upgrade pip
    Info 'Installing SecForge (Python)…'
    & $venvPy -m pip install --quiet -e $InstallDir
}

# ── Build the Web UI (optional) ──────────────────────────────────────────────
function Build-Frontend {
    $fe = Join-Path $InstallDir 'frontend'
    if ((Have 'npm') -and (Test-Path (Join-Path $fe 'package.json'))) {
        Info 'Building the Web UI (npm)…'
        Push-Location $fe
        try { npm install --no-fund --no-audit; npm run build } finally { Pop-Location }
    } else {
        Warn 'Skipping Web UI build (npm not available). The Terminal UI will still work.'
        Warn "Later: cd `"$fe`"; npm install; npm run build"
    }
}

# ── Put `secforge` on PATH ───────────────────────────────────────────────────
function Install-Shim {
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
    $venvSecforge = Join-Path $InstallDir '.venv\Scripts\secforge.exe'
    $shim = Join-Path $BinDir 'secforge.cmd'
    # CMD shim so `secforge` works from PowerShell, cmd.exe, and Run dialog.
    "@echo off`r`n`"$venvSecforge`" %*" | Out-File -FilePath $shim -Encoding ascii
    Info "Installed launcher: $shim"

    $userPath = [Environment]::GetEnvironmentVariable('Path','User')
    if (($userPath -split ';') -notcontains $BinDir) {
        Info "Adding $BinDir to your user PATH"
        [Environment]::SetEnvironmentVariable('Path', ($userPath.TrimEnd(';') + ';' + $BinDir), 'User')
        $env:Path = $env:Path + ';' + $BinDir
        Warn 'PATH updated — open a NEW terminal for `secforge` to be found everywhere.'
    }
}

# ── Main ─────────────────────────────────────────────────────────────────────
Ensure-Prereqs
Fetch-Repo
Setup-Python
Build-Frontend
Install-Shim
Write-Host ''
Info 'Done. Start SecForge with:'
Write-Host ''
Write-Host '    secforge' -ForegroundColor Green
Write-Host ''
Info 'It opens an interactive menu (Web UI / Terminal UI). The Web UI serves at http://localhost:61022'
