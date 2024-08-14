param (
    [string]$ARG_PKG_NAME="com.gzcc.gzxymnq",
    [string]$ARG_PID="-1"
)

Write-Host "Start $ARG_PKG_NAME" -ForegroundColor Green

& adb shell monkey -p $ARG_PKG_NAME -c android.intent.category.LAUNCHER 1

$tt = & adb shell su -c ls
if ($null -eq $tt) {
    $tt = ""
} else {
    $tt = " su -c "
}

Start-Sleep -s 1

if ($ARG_PID -eq "-1") {
    $ARG_PID = adb shell pidof $ARG_PKG_NAME
}

Write-Host "PID: $ARG_PID" -ForegroundColor Green

adb shell $tt setenforce 0

# build\arm64-v8a\uinjector /data/local/tmp/uinjector
adb push $PSScriptRoot/build/arm64-v8a/uinjector "/data/local/tmp/uinjector"

adb shell $tt chmod 777 /data/local/tmp/uinjector

adb shell su -c ./data/local/tmp/uinjector $ARG_PID

# then you can use nc to connect to the target process
# default port is 8024 { exapmple : nc 127.0.0.1 8024 }

# use lua binding functions