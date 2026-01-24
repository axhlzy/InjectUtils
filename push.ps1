# 用途: 推送注入库到目标应用的 lib 目录
# 功能: 自动检测架构，推送编译好的注入库到应用目录
# 用法: .\push.ps1 [-ApkName "包名"] [-InjectLib "库路径"] [-renameTo "目标名称"]

param (
    [string]$ApkName = "com.tencent.tmgp.dpcq",
    [string]$InjectLib = "prebuilt/arm64-v8a/libuinjector.so",
    [string]$renameTo = "libinject.so"
)

if ([string]::IsNullOrWhiteSpace($ApkName)) {
    Write-Host "Usage: push.ps1 [-ApkName <package_name>] [-InjectLib <lib_path>] [-renameTo <target_name>]" -ForegroundColor Yellow
    exit 0
}

Write-Host "Pushing inject library to $ApkName" -ForegroundColor Green

# 检查 root 权限
$tt = & adb shell su -c ls 2>$null
$suPrefix = if ($null -eq $tt) { "" } else { " su -c " }

# 获取包路径
$path = & adb shell pm path $ApkName
if ([string]::IsNullOrWhiteSpace($path)) {
    Write-Host "Package not found: $ApkName" -ForegroundColor Red
    exit 1
}

# 解析库路径
$relPath = $path.Split(":")[1].Replace("base.apk", "lib")
$arch = & adb shell $suPrefix ls $relPath

# 根据架构调整库路径
if ($arch -eq "arm") {
    $InjectLib = $InjectLib.Replace("arm64-v8a", "armeabi-v7a")
    Write-Host "Detected ARM32 architecture" -ForegroundColor Yellow
}
else {
    Write-Host "Detected architecture: $arch" -ForegroundColor Yellow
}

$libPath = "$relPath/$arch"
Write-Host "Target library path: $libPath" -ForegroundColor Cyan

# 检查源文件是否存在
if (!(Test-Path $InjectLib)) {
    Write-Host "Inject library not found: $InjectLib" -ForegroundColor Red
    Write-Host "Please build the project first" -ForegroundColor Yellow
    exit 1
}

# 推送库文件
Write-Host "Pushing $InjectLib..." -ForegroundColor Cyan
& adb push $InjectLib "/data/local/tmp/$renameTo"

# 复制到目标目录
& adb shell $suPrefix cp "/data/local/tmp/$renameTo" "$libPath/$renameTo"
& adb shell $suPrefix chmod 777 "$libPath/$renameTo"

# 验证
$result = & adb shell ls -lh "$libPath/$renameTo" 2>$null
if ([string]::IsNullOrWhiteSpace($result)) {
    Write-Host "Failed to push library" -ForegroundColor Red
    exit 1
}

Write-Host "`nLibrary pushed successfully!" -ForegroundColor Green
Write-Host "Location: $libPath/$renameTo" -ForegroundColor Gray