param (
    [string]$ApkName="com.tencent.tmgp.dpcq",
    [string]$InjectLib="prebuilt/arm64-v8a/libuinjector.so",
    [string]$renameTo="libinject.so"
)

if ($ApkName -eq "") {
    Write-Host "Use: push.ps1 [ApkName] [InjectLib]"
    exit 0
}

$tt = & adb shell su -c ls
if ($null -eq $tt) {
    $tt = ""
} else {
    $tt = " su -c "
}

$path = & adb shell pm path $ApkName

if ($path.Length -eq 0) {
    Write-Host "Package not found: $ApkName" -ForegroundColor Red
    exit -1
}

$relPath = $path.Split(":")[1].Replace("base.apk", "lib")

$arch = & adb shell $tt ls $relPath

if ($arch -eq "arm") {
    # replace local so path which will push
    $InjectLib = $InjectLib.Replace("arm64-v8a", "armeabi-v7a")
}

$libPath = $relPath + "/" + $arch
Write-Host $libPath

# check file exist ? $InjectLib
if (!(Test-Path $InjectLib)) {
    Write-Host "$InjectLib not found | Build it first" -ForegroundColor Red
    exit -1
}

& adb push $InjectLib "/data/local/tmp/libinject.so"
& adb shell $tt cp "/data/local/tmp/libinject.so" $($libPath + "/" + $renameTo)
& adb shell $tt chmod 777 $($libPath + '/' + $renameTo)

Write-Host "libinject.so pushd" -ForegroundColor Green