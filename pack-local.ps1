<#
.SYNOPSIS
    Builds, tests and packs every kdyf.Authorization package and publishes them to a local NuGet feed.

.DESCRIPTION
    Every package gets the same version. By default the suffix is unique per run (local.yyyyMMddHHmmss):
    NuGet caches a package by id and version in %USERPROFILE%\.nuget\packages, so packing the same version twice
    would leave consumers on the old bits without telling anyone.

.EXAMPLE
    .\pack-local.ps1
    .\pack-local.ps1 -Suffix preview.2
    .\pack-local.ps1 -Feed D:\feeds\local -SkipTests
#>
param(
    [string] $Feed = 'C:\Nuget',
    [string] $Suffix = ('local.' + (Get-Date -Format 'yyyyMMddHHmmss')),
    [string] $Configuration = 'Release',
    [switch] $SkipTests
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$solution = Join-Path $root 'kdyf.Authorization.slnx'
$output = Join-Path $root 'artifacts\packages'

function Invoke-Step([string] $title, [scriptblock] $command) {
    Write-Host "`n== $title" -ForegroundColor Cyan
    & $command
    if ($LASTEXITCODE -ne 0) { throw "$title failed (exit code $LASTEXITCODE)." }
}

if (-not (Test-Path $Feed)) { New-Item -ItemType Directory -Path $Feed | Out-Null }
if (Test-Path $output) { Remove-Item -Recurse -Force $output }

Invoke-Step "Build ($Configuration, suffix $Suffix)" {
    dotnet build $solution -c $Configuration "-p:VersionSuffix=$Suffix"
}

if (-not $SkipTests) {
    Invoke-Step 'Test' { dotnet test $solution -c $Configuration --no-build }
}

Invoke-Step 'Pack' {
    dotnet pack $solution -c $Configuration --no-build "-p:VersionSuffix=$Suffix" -o $output
}

$packages = Get-ChildItem $output -Filter '*.nupkg' | Where-Object { $_.Name -notlike '*.snupkg' }
foreach ($package in $packages) {
    Invoke-Step "Push $($package.Name)" { dotnet nuget push $package.FullName --source $Feed }
}

$prefix = ([xml](Get-Content (Join-Path $PSScriptRoot 'Directory.Build.props') -Raw)).Project.PropertyGroup.VersionPrefix | Where-Object { $_ } | Select-Object -First 1
$version = "$prefix-$Suffix"
Write-Host "`nPublished $($packages.Count) packages, version $version, to $Feed" -ForegroundColor Green
Write-Host "Consumers: add '$Feed' to their NuGet.config and reference version $version."
