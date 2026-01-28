# 用途: 注入工具到目标应用进程
# 功能: 启动应用、获取PID、推送注入器并执行注入
# 用法: .\inject.ps1 [-ARG_PKG_NAME "包名"] [-ARG_PID "进程ID"]

param (
    [string]$ARG_PKG_NAME = "com.gzcc.gzxymnq",
    [string]$ARG_PID = "-1"
)

Write-Host "Starting injection for $ARG_PKG_NAME" -ForegroundColor Green

# 启动应用
& adb shell monkey -p $ARG_PKG_NAME -c android.intent.category.LAUNCHER 1

# 检查是否有 root 权限
$tt = & adb shell su -c ls 2>$null
$suPrefix = if ($null -eq $tt) { "" } else { " su -c " }

Start-Sleep -Seconds 1

# 获取进程 PID
if ($ARG_PID -eq "-1") {
    $ARG_PID = & adb shell pidof $ARG_PKG_NAME
    if ([string]::IsNullOrWhiteSpace($ARG_PID)) {
        Write-Host "Failed to get PID for $ARG_PKG_NAME" -ForegroundColor Red
        exit 1
    }
}

Write-Host "Target PID: $ARG_PID" -ForegroundColor Green

# 禁用 SELinux
& adb shell $suPrefix setenforce 0

# 推送注入器
$injectorPath = "$PSScriptRoot/../../prebuilt/arm64-v8a/uinjector"
if (!(Test-Path $injectorPath)) {
    Write-Host "Injector not found: $injectorPath" -ForegroundColor Red
    Write-Host "Please build the project first" -ForegroundColor Yellow
    exit 1
}

Write-Host "Pushing injector..." -ForegroundColor Cyan
& adb push $injectorPath "/data/local/tmp/uinjector"

# 设置执行权限
& adb shell $suPrefix chmod 777 /data/local/tmp/uinjector

# 执行注入
Write-Host "Injecting into process $ARG_PID..." -ForegroundColor Cyan
& adb shell su -c ./data/local/tmp/uinjector -p $ARG_PID

Write-Host "`Injection complete!" -ForegroundColor Green
Write-Host "You can now connect using: nc 127.0.0.1 8024" -ForegroundColor Yellow