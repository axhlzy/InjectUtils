param (
    [string]$pkgName="com.tencent.tmgp.dpcq"
)

& adb shell am force-stop $pkgName
& adb shell monkey -p $pkgName -c android.intent.category.LAUNCHER 1

$id = & adb shell pidof $pkgName

Write-Host "PID: $id"

# $tt = & adb shell su -c ls
# if ($null -eq $tt) {
#     $tt = ""
# } else {
#     $tt = " su -c "
# }

# & adb shell $tt kill -s SIGSTOP $id

# resume the app
# & adb shell $tt kill -s SIGCONT $id