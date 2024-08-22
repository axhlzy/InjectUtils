$ScriptLocal = $PSScriptRoot

if ([System.Environment]::OSVersion.Platform -eq "Unix") {
    Write-Host "bin2h on Linux or macOS"
    if (-not (Test-Path $ScriptLocal\bin2h)) {
        Write-Host "bin2h not found, compiling..." -ForegroundColor Yellow
        clang -O3 -o $ScriptLocal\bin2h $ScriptLocal\bin2h.c
        Write-Host "build out => bin2h" -ForegroundColor Green
        chmod +x bin2h
    }
    else {
        Write-Host "bin2h found | pass build" -ForegroundColor Green
    }
    $bin2hExecutable = "$ScriptLocal/bin2h"
}
elseif ([System.Environment]::OSVersion.Platform -eq "Win32NT") {
    Write-Host "bin2h on Windows"
    if (-not (Test-Path $ScriptLocal\bin2h.exe)) {
        Write-Host "bin2h.exe not found, compiling..." -ForegroundColor Yellow
        clang -O3 -o $ScriptLocal\bin2h.exe $ScriptLocal\bin2h.c
        Write-Host "build out => bin2h.exe" -ForegroundColor Green
    }
    else {
        Write-Host "bin2h.exe found | pass build" -ForegroundColor Green
    }
    $bin2hExecutable = "$ScriptLocal/bin2h.exe"
}

Write-Host "bin2h executable: $bin2hExecutable"

if (-not (Test-Path $ScriptLocal\temp)) {
    New-Item -ItemType Directory -Path $ScriptLocal\temp | Out-Null
}

$fileName = Get-ChildItem -Path $ScriptLocal\temp -Filter *.so | Select-Object -ExpandProperty Name

if ($null -eq $fileName) {
    Write-Host "no .so file found" -ForegroundColor Red
    exit 1
} else {
    Write-Host "found .so file: $fileName" -ForegroundColor Green
    Write-Host "convert .so to .h" -ForegroundColor Yellow
    & $bin2hExecutable -s -i $ScriptLocal\temp\$fileName -o $ScriptLocal\temp\tohex.h
}