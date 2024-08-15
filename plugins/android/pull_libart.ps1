param (
    [string]$ARCH="arm64-v8a"
)
Write-Output $ARCH

if ($ARCH -eq "armeabi-v7a") {
    $lib = "/apex/com.android.runtime/lib/libart.so"
} elseif ($ARCH -eq "arm64-v8a") {
    $lib = "/apex/com.android.art/lib64/libart.so"
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

& adb pull $lib "${PSScriptRoot}/libraries/${ARCH}/"

Pop-Location

Pop-Location