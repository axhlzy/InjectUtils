# 用途: 启动目标应用
# 功能: 强制停止并重新启动应用，获取进程ID
# 用法: .\start.ps1 [-pkgName "包名"]

param (
    [string]$pkgName = "com.tencent.tmgp.dpcq"
)

if ([string]::IsNullOrWhiteSpace($pkgName)) {
    Write-Host "Usage: start.ps1 [-pkgName <package_name>]" -ForegroundColor Yellow
    exit 0
}

Write-Host "Starting application: $pkgName" -ForegroundColor Green

# 强制停止应用
Write-Host "Force stopping..." -ForegroundColor Cyan
& adb shell am force-stop $pkgName

Start-Sleep -Milliseconds 500

# 启动应用
Write-Host "Launching..." -ForegroundColor Cyan
& adb shell monkey -p $pkgName -c android.intent.category.LAUNCHER 1

Start-Sleep -Seconds 1

# 获取进程 ID
$pid = & adb shell pidof $pkgName

if ([string]::IsNullOrWhiteSpace($pid)) {
    Write-Host "Failed to get PID. Application may not have started." -ForegroundColor Red
    exit 1
}

Write-Host "`nApplication started successfully!" -ForegroundColor Green
Write-Host "Package: $pkgName" -ForegroundColor Gray
Write-Host "PID:     $pid" -ForegroundColor Yellow

# 可选：暂停应用进程（用于调试）
# $tt = & adb shell su -c ls 2>$null
# $suPrefix = if ($null -eq $tt) { "" } else { " su -c " }
# & adb shell $suPrefix kill -s SIGSTOP $pid
# Write-Host "Process paused (SIGSTOP)" -ForegroundColor Yellow
# 
# 恢复应用进程：
# & adb shell $suPrefix kill -s SIGCONT $pid
