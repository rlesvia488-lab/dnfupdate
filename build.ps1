$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$lib = Join-Path $root "lib"
$build = Join-Path $root "build"
$classes = Join-Path $build "classes"
$dist = Join-Path $root "dist"
$dep = Join-Path $lib "jsch-0.2.24.jar"
$url = "https://repo1.maven.org/maven2/com/github/mwiede/jsch/0.2.24/jsch-0.2.24.jar"

New-Item -ItemType Directory -Force -Path $lib, $classes, $dist | Out-Null
if (Test-Path $classes) {
    Remove-Item -Recurse -Force $classes
}
New-Item -ItemType Directory -Force -Path $classes | Out-Null

if (!(Test-Path $dep)) {
    Write-Host "Downloading SSH dependency..."
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $dep
}

Write-Host "Compiling..."
$sourceList = Join-Path $build "sources.txt"
Get-ChildItem -Path (Join-Path $root "src\main\java") -Recurse -Filter *.java |
    ForEach-Object { '"' + ($_.FullName -replace '\\', '/') + '"' } |
    Set-Content -Encoding ascii $sourceList
$oldErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$javacOutput = & javac "-J-Dsun.zip.disableMemoryMapping=true" --release 17 -encoding UTF-8 -cp "$dep" -d "$classes" "@$sourceList" 2>&1
$javacExit = $LASTEXITCODE
$ErrorActionPreference = $oldErrorActionPreference
if ($javacExit -ne 0) {
    $javacOutput | Write-Host
    throw "javac failed with exit code $javacExit"
}
Start-Sleep -Milliseconds 750

Write-Host "Packing dependency classes..."
Push-Location $classes
jar xf $dep
if ($LASTEXITCODE -ne 0) {
    throw "jar extract failed with exit code $LASTEXITCODE"
}
Pop-Location

$manifest = Join-Path $build "MANIFEST.MF"
@"
Manifest-Version: 1.0
Main-Class: com.dnfupdate.DnfUpdateApp

"@ | Set-Content -Encoding ascii $manifest

$jarPath = Join-Path $dist "dnf-security-update-console.jar"
if (Test-Path $jarPath) {
    Remove-Item $jarPath
}

Write-Host "Creating $jarPath"
Push-Location $classes
jar cfm $jarPath $manifest .
if ($LASTEXITCODE -ne 0) {
    throw "jar create failed with exit code $LASTEXITCODE"
}
Pop-Location

$startScript = Join-Path $root "start.sh"
if (Test-Path $startScript) {
    Copy-Item -Force $startScript (Join-Path $dist "start.sh")
    Write-Host "Copied start.sh to dist\start.sh"
}

Write-Host "Done."
Write-Host "Run with: java -jar dist\dnf-security-update-console.jar"
