param (
    [string]$pkgName="com.jywsqk.jh.jh"
)

$CURR = (Get-Item -Path ".\" -Verbose).FullName

& adb push ${CURR}\prebuilt\arm64-v8a\uinjector "/data/local/tmp/uinjector"

$tt = & adb shell su -c ls
if ($null -eq $tt) {
    $tt = ""
} else {
    $tt = " su -c "
}

& adb shell ${$tt} "chmod +x /data/local/tmp/uinjector"

& Start-Process powershell "adb shell ${$tt} ./data/local/tmp/uinjector -p ${$pkgName}"