# 用途: 列出设备上的应用包信息
# 功能: 显示包名、路径、调试状态、启动Activity、架构、版本等详细信息
# 用法: .\pkgs.ps1 [-filterPkgName "过滤关键字"]

param (
    [string]$filterPkgName = ""
)

Write-Host "Fetching package list..." -ForegroundColor Cyan

# 获取包列表
$packages = & adb shell pm list packages
$filteredPackages = $packages -replace "^package:", "" | Where-Object { $_ -match $filterPkgName }

if ($filteredPackages.Length -eq 0) {
    Write-Host "No packages found matching '$filterPkgName'" -ForegroundColor Yellow
    exit 0
}

Write-Host "Found $($filteredPackages.Length) package(s)`n" -ForegroundColor Green

$index = 0
$filteredPackages | ForEach-Object {
    $pkgName = $_
    
    # 获取包路径
    $pkgPath = & adb shell pm path $pkgName
    $pkgPath = $pkgPath -replace "^package:", ""

    # 获取包详细信息
    $dumpsysOutput = & adb shell dumpsys package $pkgName
    
    # 检查是否可调试
    $isDebug = if ($dumpsysOutput -match "pkgFlags=\[.*DEBUGGABLE.*\]") { "Yes" } else { "No" }

    # 查找主 Activity
    $mainActivity = ""
    $isMainAction = $false
    $isLauncherCategory = $false
    $candidateActivity = ""
    
    $dumpsysOutput -split "`n" | ForEach-Object {
        $line = $_
        if ($line -match "android.intent.action.MAIN") {
            $isMainAction = $true
        }
        if ($line -match "category.LAUNCHER") {
            $isLauncherCategory = $true
        }
        if ($isMainAction -and !$isLauncherCategory -and $line -match "([^\s]+)/([^\s]+)") {
            $candidateActivity = $matches[0]
        }
        if ($isMainAction -and $isLauncherCategory -and $candidateActivity) {
            $mainActivity = $candidateActivity
            $isMainAction = $false
            $isLauncherCategory = $false
            $candidateActivity = ""
        }
    }

    # 提取其他信息
    $userId = ""
    $primaryCpuAbi = "N/A"
    $secondaryCpuAbi = "N/A"
    $versionCode = ""
    $minSdk = ""
    $targetSdk = ""
    $versionName = ""
    $apkSigningVersion = ""

    $dumpsysOutput -split "`n" | ForEach-Object {
        $line = $_
        if ($line -match "userId=(\d+)") { $userId = $matches[1] }
        if ($line -match "primaryCpuAbi=([^\s]+)") { $primaryCpuAbi = $matches[1] }
        if ($line -match "secondaryCpuAbi=([^\s]+)") { $secondaryCpuAbi = $matches[1] }
        if ($line -match "versionCode=(\d+)") { $versionCode = $matches[1] }
        if ($line -match "minSdk=(\d+)") { $minSdk = $matches[1] }
        if ($line -match "targetSdk=(\d+)") { $targetSdk = $matches[1] }
        if ($line -match "versionName=([\d\.]+)") { $versionName = $matches[1] }
        if ($line -match "apkSigningVersion=(\d+)") { $apkSigningVersion = $matches[1] }
    }

    # 显示信息
    Write-Host "[$index] $pkgName" -ForegroundColor Green
    Write-Host "  Path:              $pkgPath" -ForegroundColor Gray
    Write-Host "  Debuggable:        $isDebug" -ForegroundColor $(if ($isDebug -eq "Yes") { "Yellow" } else { "Gray" })
    Write-Host "  Launcher Activity: $mainActivity" -ForegroundColor Gray
    Write-Host "  User ID:           $userId" -ForegroundColor Gray
    Write-Host "  Primary ABI:       $primaryCpuAbi" -ForegroundColor Gray
    Write-Host "  Secondary ABI:     $secondaryCpuAbi" -ForegroundColor Gray
    Write-Host "  Version:           $versionName ($versionCode)" -ForegroundColor Gray
    Write-Host "  SDK:               Min=$minSdk, Target=$targetSdk" -ForegroundColor Gray
    Write-Host "  Signing Version:   $apkSigningVersion" -ForegroundColor Gray
    Write-Host ""
    
    $index++
}

Write-Host "Total: $index package(s)" -ForegroundColor Cyan
