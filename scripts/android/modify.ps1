# 用途: 修改 APK 的 native 库，添加注入库依赖
# 功能: 备份原始 so 文件，使用 LIEF 修改 so 添加 libinject.so 依赖
# 用法: .\modify.ps1 [-ApkName "包名"] [-restore $True/$False]

param (
    [string]$ApkName = "com.tencent.tmgp.dpcq",
    [bool]$restore = $False
)

if ([string]::IsNullOrWhiteSpace($ApkName)) {
    Write-Host "Usage: modify.ps1 [-ApkName <package_name>] [-restore `$True/`$False]" -ForegroundColor Yellow
    exit 0
}

Write-Host "Processing package: $ApkName" -ForegroundColor Green

# 检查 root 权限
$tt = & adb shell su -c ls 2>$null
$suPrefix = if ($null -eq $tt) { "" } else { " su -c " }

# 获取 APK 路径
$path = & adb shell pm path $ApkName
if ([string]::IsNullOrWhiteSpace($path)) {
    Write-Host "Package not found: $ApkName" -ForegroundColor Red
    exit 1
}

# 解析库路径
$relPath = $path.Split(":")[1].Replace("base.apk", "lib")
$arch = & adb shell ls $relPath
$libPath = "$relPath/$arch"

Write-Host "Library path: $libPath" -ForegroundColor Yellow

# 获取 so 文件列表
$listSo = & adb shell ls $libPath
if ([string]::IsNullOrWhiteSpace($listSo)) {
    Write-Host "No libraries found in $libPath" -ForegroundColor Red
    exit 1
}

# 过滤 .so 文件
$listSoFiltered = $listSo -split "`n" | Where-Object { $_ -match "\.so$" }
if ($listSoFiltered.Length -eq 0) {
    Write-Host "No .so files found in $libPath" -ForegroundColor Red
    exit 1
}

# 显示可选的 so 文件
Write-Host "`nAvailable libraries:" -ForegroundColor Cyan
$i = 0
$listSoFiltered | ForEach-Object {
    Write-Host ("[{0}] {1}" -f $i++, $_) -ForegroundColor Magenta
}

# 选择要修改的 so 文件
$index = Read-Host "`nEnter the index of the library to modify"
if ($index -notmatch "^\d+$" -or $index -lt 0 -or $index -ge $listSoFiltered.Length) {
    Write-Host "Invalid index" -ForegroundColor Red
    exit 1
}

$selectedSo = $listSoFiltered[$index]
$mdLibFullName = "$libPath/$selectedSo"
$bkLibFullName = "$libPath/${selectedSo}_BK"

# 创建临时目录
$tempDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "$(Get-Date -Format 'yyyyMMddHHmmss')_LIBTMP")
New-Item -ItemType Directory -Path $tempDir | Out-Null
Push-Location $tempDir

try {
    # 拉取原始文件
    & adb pull $mdLibFullName

    if ($restore) {
        # 恢复模式
        $file = & adb shell ls $bkLibFullName 2>$null
        if ([string]::IsNullOrWhiteSpace($file)) {
            Write-Host "Backup not found: ${selectedSo}_BK" -ForegroundColor Red
            exit 1
        }
        
        & adb shell $suPrefix rm $mdLibFullName
        & adb shell $suPrefix cp $bkLibFullName $mdLibFullName
        & adb shell $suPrefix chmod 777 $mdLibFullName
        Write-Host "$selectedSo restored successfully" -ForegroundColor Green
    }
    else {
        # 修改模式
        # 备份原始文件
        & adb shell $suPrefix cp $mdLibFullName $bkLibFullName
        Write-Host "$selectedSo backed up as ${selectedSo}_BK" -ForegroundColor Green

        # 使用 LIEF 修改 so 文件
        $localmdSo = $selectedSo.Replace(".so", "_modified.so")
        $py_add_library = @"
import lief
lf = lief.parse(r'$selectedSo')
lf.add_library(r'libinject.so')
lf.write(r'$localmdSo')
"@

        Write-Host "Modifying library with LIEF..." -ForegroundColor Cyan
        & python -c $py_add_library

        if (!(Test-Path $localmdSo)) {
            Write-Host "Failed to modify library. Make sure LIEF is installed: pip install lief" -ForegroundColor Red
            exit 1
        }

        # 推送修改后的文件
        & adb push $localmdSo "/data/local/tmp/$selectedSo"
        & adb shell $suPrefix cp "/data/local/tmp/$selectedSo" $libPath
        & adb shell $suPrefix chmod 777 $mdLibFullName

        Write-Host "`nModified library info:" -ForegroundColor Cyan
        & adb shell ls -lh $libPath

        Write-Host "`nModification complete!" -ForegroundColor Green
    }
}
finally {
    # 清理临时目录
    Pop-Location
    Remove-Item $tempDir -Recurse -Force -ErrorAction SilentlyContinue
}