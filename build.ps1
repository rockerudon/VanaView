# Build script for the VanaView Ashita plugin.
#
# Requirements:
#   - Visual Studio 2022 with the C++ x86 (32-bit) build tools.
#   - The Ashita v4 plugin SDK headers.
#
# Set ASHITA_SDK to the Ashita plugin SDK folder that contains Ashita.h.
# FFXI is a 32-bit process, so this builds x86.

$ErrorActionPreference = 'Stop'

$root     = $PSScriptRoot
$src      = Join-Path $root 'src\VanaView.cpp'
$buildDir = Join-Path $root 'build'
$distDir  = Join-Path $root 'dist'
$outDll   = Join-Path $distDir 'VanaView.dll'
$obj      = Join-Path $buildDir 'VanaView.obj'

$sdk = $env:ASHITA_SDK
if ([string]::IsNullOrWhiteSpace($sdk) -or -not (Test-Path (Join-Path $sdk 'Ashita.h'))) {
    throw 'Ashita SDK not found. Set ASHITA_SDK to the folder that contains Ashita.h.'
}

$vcvarsCandidates = @(
    'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat',
    'C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat',
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat'
)

$vcvars = $vcvarsCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $vcvars) {
    throw 'Could not find Visual Studio vcvars32.bat. Install the Visual Studio C++ x86 build tools.'
}

New-Item -ItemType Directory -Force $buildDir | Out-Null
New-Item -ItemType Directory -Force $distDir  | Out-Null

$clArgs = @(
    '/nologo',
    '/std:c++20',
    '/EHa',
    '/O2',
    '/MT',
    '/LD',
    '/W3',
    '/D_CRT_SECURE_NO_WARNINGS',
    "/I`"$sdk`"",
    "/Fe:`"$outDll`"",
    "/Fo:`"$obj`"",
    "`"$src`""
) -join ' '

$command = "`"$vcvars`" >nul && cl.exe $clArgs"
cmd.exe /c $command
if ($LASTEXITCODE -ne 0) {
    throw "VanaView build failed with exit code $LASTEXITCODE."
}

& (Join-Path $root 'tools\Test-Plugin.ps1') -PluginPath $outDll

Write-Host "Built: $outDll"
Write-Host 'Copy it to Ashita/plugins/ and load it in game with: /load vanaview'
