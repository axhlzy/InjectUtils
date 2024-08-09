param (
    [string]$ApkName="com.tencent.tmgp.dpcq",
    [bool]$restore=$False
)

if ($ApkName -eq "") {
    Write-Host "Use: modify.ps1 [ApkName]"
    exit 0
}

Write-Host "Modifying $ApkName"

$tt = & adb shell su -c ls
if ($null -eq $tt) {
    $tt = ""
} else {
    $tt = " su -c "
}

# package:/data/app/~~NbU8IL9vIx8EGxYon4G4vA==/com.tencent.tmgp.dpcq-mj_fanDdQ6ADzQZImgeVHA==/base.apk
$path = & adb shell pm path $ApkName

if ($path.Length -eq 0) {
    Write-Host "Package not found: $ApkName" -ForegroundColor Red
    exit -1
}

# /data/app/~~NbU8IL9vIx8EGxYon4G4vA==/com.tencent.tmgp.dpcq-mj_fanDdQ6ADzQZImgeVHA==/lib
$relPath = $path.Split(":")[1].Replace("base.apk", "lib")

$arch = & adb shell ls $relPath

$libPath = $relPath + "/" + $arch
Write-Host $libPath  -ForegroundColor Yellow

$listSo = & adb shell ls $libPath

# Check if the list is empty
if ($listSo.Length -eq 0) {
    Write-Host "No so found in $libPath" -ForegroundColor Red
    exit -1
} else {
    # Filter the list to include only .so files
    $listSoFiltered = $listSo -split "`n" | Where-Object { $_ -match "\.so$" }

    # Check if there are any .so files after filtering
    if ($listSoFiltered.Length -eq 0) {
        Write-Host "No .so files found in $libPath" -ForegroundColor Red
        exit -1
    }

    # Display the list of .so files with indices
    $i = 0
    $listSoFiltered | ForEach-Object {
        Write-Host ("[{0}] {1}" -f $i++, $_) -ForegroundColor Magenta
    }

    # Prompt the user to select an index
    $index = Read-Host "Enter the index of the so file"

    # # Check if the entered index is valid
    # if ($index -match "^\d+$" -and $index -ge 0 -and $index -lt $listSoFiltered.Length) {
        $selectedSo = $listSoFiltered[$index]
    #     Write-Host "You selected: $selectedSo" -ForegroundColor Green
    # } else {
    #     Write-Host "Invalid index entered. Exiting." -ForegroundColor Red
    #     exit -1
    # }
}

$tempDir = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $(Get-Date -Format "yyyyMMddHHmmss") + "_LIBTMP")

New-Item -ItemType Directory -Path $tempDir | Out-Null

Push-Location $tempDir

$mdLibFullName = $($libPath + "/" + $selectedSo)
$bkLibFullName = $($libPath + "/" + $selectedSo + "_BK")

& adb pull $mdLibFullName

if ($restore) {
    $file = & adb shell ls $mdLibFullName
    if ($file -eq "") {
        Write-Host "$($selectedSo) not found in $libPath" -ForegroundColor Red
    } else {
        & adb shell $tt rm $mdLibFullName
        & adb shell $tt cp $bkLibFullName $mdLibFullName
        & adb shell $tt chmod 777 $mdLibFullName
        Write-Host "$($selectedSo) restored" -ForegroundColor Green
        Remove-Item $tempDir -Recurse -Force
        Pop-Location
        exit 0
    }
} else {
    & adb shell $tt cp $mdLibFullName $bkLibFullName
    Write-Host "$($selectedSo) backed up" -ForegroundColor Green
}

$localmdSo = $selectedSo.Replace(".so", "_modified.so")

$py_add_library = @"
import lief
lf = lief.parse(r'${selectedSo}')
lf.add_library(r'libinject.so')
lf.write(r"${localmdSo}")
"@

& python -c $py_add_library

& adb push ${localmdSo} "/data/local/tmp/$($selectedSo)"
& adb shell $tt cp "/data/local/tmp/$($selectedSo)" $libPath
& adb shell $tt chmod 777 $mdLibFullName

& adb shell ls -lh $libPath

Pop-Location

Remove-Item $tempDir -Recurse -Force

Write-Host "Modification complete" -ForegroundColor Green