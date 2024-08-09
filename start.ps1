param (
    [string]$ApkName="com.tencent.tmgp.dpcq"
)

& adb shell am force-stop $ApkName
& adbe start $ApkName

$id = & adb shell pidof $ApkName

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