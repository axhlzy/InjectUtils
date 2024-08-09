param (
    [string]$ARCH="arm64-v8a"
)

$lib = ""
if ($ARCH -eq "armeabi-v7a") {
    $lib = "lib"
} elseif ($ARCH -eq "arm64-v8a") {
    $lib = "lib64"
}

Push-Location $PSScriptRoot

if (Test-Path libraries) {
    Remove-Item -Recurse -Force libraries
}

New-Item -ItemType directory -Name libraries

Push-Location libraries

if (Test-Path $ARCH) {
    Remove-Item -Recurse -Force $ARCH
}

New-Item -ItemType directory -Name $ARCH

& adb pull "/apex/com.android.art/$lib/libart.so" "$($PSScriptRoot)/libraries/$($ARCH)/"

Pop-Location

Pop-Location