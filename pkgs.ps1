param (
    [string]$filterPkgName=""
)

$packages = & adb shell pm list packages

$filteredPackages = $packages -replace "^package:", "" | Where-Object { $_ -match $filterPkgName }

$filteredPackages | ForEach-Object {
    $pkgName = $_
    $pkgPath = & adb shell pm path $pkgName
    $pkgPath = $pkgPath -replace "^package:", ""

    $dumpsysOutput = & adb shell dumpsys package $pkgName
    $isDebug = if ($dumpsysOutput -match "pkgFlags=\[.*DEBUGGABLE.*\]") { $true } else { $false }

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

    $userId = ""
    $primaryCpuAbi = ""
    $secondaryCpuAbi = ""
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

    Write-Host "[$($filteredPackages.IndexOf($pkgName))] $pkgName" -ForegroundColor Green
    Write-Host "`tpath: $pkgPath" -ForegroundColor Magenta
    Write-Host "`tisDebug: $isDebug" -ForegroundColor Cyan
    Write-Host "`tluncherActivity: $mainActivity" -ForegroundColor Yellow
    Write-Host "`tuserId: $userId" -ForegroundColor Blue
    Write-Host "`tprimaryCpuAbi: $primaryCpuAbi" -ForegroundColor Magenta
    Write-Host "`tsecondaryCpuAbi: $secondaryCpuAbi" -ForegroundColor Cyan
    Write-Host "`tversionCode: $versionCode" -ForegroundColor Yellow
    Write-Host "`tminSdk: $minSdk" -ForegroundColor Blue
    Write-Host "`ttargetSdk: $targetSdk" -ForegroundColor Magenta
    Write-Host "`tversionName: $versionName" -ForegroundColor Cyan
    Write-Host "`tapkSigningVersion: $apkSigningVersion" -ForegroundColor Yellow
}
