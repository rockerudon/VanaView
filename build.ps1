# Build script for the VanaView Ashita plugin.
#
# Requirements:
#   - Visual Studio 2022 with the C++ x86 (32-bit) build tools.
#   - The Ashita v4 plugin SDK headers.
#
# The script auto-detects the CatsEyeXI Ashita SDK, or you can override it
# with the ASHITA_SDK environment variable. FFXI is a 32-bit process, so this builds x86.

$ErrorActionPreference = 'Stop'

$root     = $PSScriptRoot
$src      = Join-Path $root 'src\VanaView.cpp'
$buildDir = Join-Path $root 'build'
$distDir  = Join-Path $root 'dist'
$outDll   = Join-Path $distDir 'VanaView.dll'
$obj      = Join-Path $buildDir 'VanaView.obj'

$sdkCandidates = @(
    $env:ASHITA_SDK,
    'C:\Games\CatsEyeXI\catseyexi-client\Ashita\plugins\sdk'
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

$sdk = $sdkCandidates | Where-Object { Test-Path (Join-Path $_ 'Ashita.h') } | Select-Object -First 1
if (-not $sdk) {
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

Write-Host "Built: $outDll"
Write-Host 'Copy it to Ashita/plugins/ and load it in game with: /load vanaview'
