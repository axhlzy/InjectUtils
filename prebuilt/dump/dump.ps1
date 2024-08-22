param (
    [string]$PKG_NAME="com.qnssxszaz.qy",
    [string]$LIB_NAME="libbaiduprotect.so",
    [string]$ARCH="arm64-v8a"
)

if ($PKG_NAME -eq "" -or $LIB_NAME -eq "") {
    Write-Host "Usage:  -p <package name> -l <library name>" -ForegroundColor Red
    exit 1
}

Set-Location $PSScriptRoot

$memdumper = ""
if ($ARCH -eq "arm64-v8a") {
    $memdumper = "memdumper64"
} elseif ($ARCH -eq "armeabi-v7a") {
    $memdumper = "memdumper"
} else {
    Write-Host "Unsupported architecture: $ARCH" -ForegroundColor Red
    exit 1
}

$tt = & adb shell su -c ls
if ($null -eq $tt) {
    $tt = ""
} else {
    $tt = " su -c "
}

& adb push $memdumper "/data/local/tmp/mmd"

& adb shell "$tt chmod 777 /data/local/tmp/mmd"

$res = & adb shell "$tt ./data/local/tmp/mmd -p $PKG_NAME -l -r -n $LIB_NAME -o /data/local/tmp/"

write-host $res
$lines = $res -split "`n"

foreach ($line in $lines) {
    if ($line -match "Base Address of $LIB_NAME Found At ([0-9a-f]+)") {
        $baseAddress = $matches[1]
        Write-Host "Base Address: $baseAddress" -ForegroundColor Green
    }
    elseif ($line -match "End Address of $LIB_NAME Found At ([0-9a-f]+)") {
        $endAddress = $matches[1]
        Write-Host "End Address: $endAddress" -ForegroundColor Green
    }
    elseif ($line -match "Lib Size: (\d+)") {
        $libSize = $matches[1]
        Write-Host "Library Size: $libSize bytes" -ForegroundColor Green
    }
}

& adb pull "/data/local/tmp/$($LIB_NAME)" .

if ($IsWindows) {
    write-host "SoFixer on Windows" -ForegroundColor Green
    & SoFixer-Windows-64.exe -m $baseAddress -d -s $($LIB_NAME) -o $($LIB_NAME)_fix
}
if ($IsLinux) {
    write-host "SoFixer on Linux" -ForegroundColor Green
    & SoFixer-Linux-64 -m $baseAddress -d -s $($LIB_NAME) -o $($LIB_NAME)_fix
}

write-host "SoFixer done" -ForegroundColor Green