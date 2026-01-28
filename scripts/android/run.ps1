# 用途: 运行注入器（调试模式）
# 功能: 推送注入器到设备并在新窗口中执行
# 用法: .\run.ps1 [-pkgName "包名"]

param (
    [string]$pkgName = "com.jywsqk.jh.jh"
)

if ([string]::IsNullOrWhiteSpace($pkgName)) {
    Write-Host "Usage: run.ps1 [-pkgName <package_name>]" -ForegroundColor Yellow
    exit 0
}

Write-Host "Running injector for $pkgName" -ForegroundColor Green

$ProjectRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$injectorPath = "$ProjectRoot\prebuilt\arm64-v8a\uinjector"

# 检查注入器是否存在
if (!(Test-Path $injectorPath)) {
    Write-Host "Injector not found: $injectorPath" -ForegroundColor Red
    Write-Host "Please build the project first" -ForegroundColor Yellow
    exit 1
}

# 推送注入器
Write-Host "Pushing injector..." -ForegroundColor Cyan
& adb push $injectorPath "/data/local/tmp/uinjector"

# 检查 root 权限
$tt = & adb shell su -c ls 2>$null
$suPrefix = if ($null -eq $tt) { "" } else { "su -c " }

# 设置执行权限
& adb shell $suPrefix chmod +x /data/local/tmp/uinjector

# 在新窗口中运行注入器
Write-Host "Starting injector in new window..." -ForegroundColor Cyan
Start-Process powershell -ArgumentList "adb shell $suPrefix ./data/local/tmp/uinjector -p $pkgName"

Write-Host "`nInjector started!" -ForegroundColor Green
