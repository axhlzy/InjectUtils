$ScriptLocal = $PSScriptRoot
$ProjectRoot = Split-Path (Split-Path $ScriptLocal -Parent) -Parent

# 检测操作系统并设置 bin2h 可执行文件路径
if ([System.Environment]::OSVersion.Platform -eq "Unix") {
    Write-Host "bin2h on Linux or macOS" -ForegroundColor Cyan
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
    Write-Host "bin2h on Windows" -ForegroundColor Cyan
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

Write-Host "bin2h executable: $bin2hExecutable" -ForegroundColor Cyan
Write-Host ""

# 处理 assets/dex 目录下的所有 DEX 文件
$dexDir = Join-Path $ProjectRoot "assets\dex"
$generatedDir = Join-Path $ProjectRoot "src\generated"

Write-Host "DEX directory: $dexDir" -ForegroundColor Cyan
Write-Host "Generated directory: $generatedDir" -ForegroundColor Cyan
Write-Host ""

# 创建生成目录
if (-not (Test-Path $generatedDir)) {
    New-Item -ItemType Directory -Path $generatedDir | Out-Null
    Write-Host "Created directory: $generatedDir" -ForegroundColor Green
}

# 查找所有 DEX 文件
$dexFiles = Get-ChildItem -Path $dexDir -Filter *.dex -ErrorAction SilentlyContinue

if ($null -eq $dexFiles -or $dexFiles.Count -eq 0) {
    Write-Host "No .dex files found in $dexDir" -ForegroundColor Yellow
    Write-Host "Skipping DEX to header conversion" -ForegroundColor Yellow
} else {
    Write-Host "Found $($dexFiles.Count) DEX file(s):" -ForegroundColor Green
    
    foreach ($dexFile in $dexFiles) {
        $dexName = $dexFile.BaseName
        $dexPath = $dexFile.FullName
        
        # 转换为小写并替换特殊字符为下划线（用于变量名）
        $varName = $dexName.ToLower() -replace '[^a-z0-9_]', '_'
        $varName = "${varName}_dex"
        
        # 生成的头文件路径
        $headerFile = Join-Path $generatedDir "${varName}.h"
        
        Write-Host "  Converting: $dexName.dex" -ForegroundColor Cyan
        Write-Host "    -> Variable: $varName" -ForegroundColor Gray
        Write-Host "    -> Header: $headerFile" -ForegroundColor Gray
        
        # 调用 bin2h 转换
        & $bin2hExecutable -s -i $dexPath -o $headerFile -n $varName
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    [OK] Generated successfully" -ForegroundColor Green
        } else {
            Write-Host "    [ERROR] Failed to generate header" -ForegroundColor Red
        }
        Write-Host ""
    }
    
    Write-Host "DEX to header conversion completed!" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan

# 处理 temp 目录下的 .so 文件（保留原有功能）
if (-not (Test-Path $ScriptLocal\temp)) {
    New-Item -ItemType Directory -Path $ScriptLocal\temp | Out-Null
}

$fileName = Get-ChildItem -Path $ScriptLocal\temp -Filter *.so -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name

if ($null -eq $fileName) {
    Write-Host "No .so file found in temp directory" -ForegroundColor Yellow
} else {
    Write-Host "Found .so file: $fileName" -ForegroundColor Green
    Write-Host "Converting .so to .h" -ForegroundColor Yellow
    & $bin2hExecutable -s -i $ScriptLocal\temp\$fileName -o $ScriptLocal\temp\tohex.h
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "SO to header conversion completed!" -ForegroundColor Green
    } else {
        Write-Host "Failed to convert .so file" -ForegroundColor Red
    }
}