param (
    [string]$RepoOwner = "lief-project",
    [string]$RepoName = "LIEF",
    [string]$TagName = "0.14.1"
)

function DownloadGitHubReleaseFile {
    param (
        [string]$RepoOwner,
        [string]$RepoName,
        [string]$TagName,
        [string]$FileName,
        [string]$OutputPath
    )

    $Url = "https://api.github.com/repos/$($RepoOwner)/$($RepoName)/releases/tags/$($TagName)"

    Write-Host "Fetching release info from $($Url)" -ForegroundColor DarkCyan

    try {
        $Response = Invoke-RestMethod -Uri $Url -Method Get -ErrorAction Stop

        foreach ($Asset in $Response.assets) {
            if ($Asset.name -eq $FileName) {
                $DownloadUrl = $Asset.browser_download_url
                if ($DownloadUrl) {
                    Invoke-WebRequest -Uri $DownloadUrl -OutFile $OutputPath
                    Write-Host "File downloaded successfully."
                    return
                }
            }
        }

        Write-Host "File not found in the release." -ForegroundColor Red
        exit -1
    }
    catch {
        Write-Error "Failed to fetch release info from $($Url)."
        exit -1
    }
}

$workingDir = $PSScriptRoot

Push-Location $workingDir

$Platform = "Android"

$ArchDir = "arm64-v8a"
# LIEF-0.14.1-Android-aarch64.tar.gz
$FileName = "$($RepoName)-$($TagName)-$($Platform)-aarch64.tar.gz"
if (-not (Test-Path $ArchDir)) {
    New-Item -ItemType Directory -Path $ArchDir

    $OutputPath = Join-Path $workingDir $ArchDir
    $OutputFile = Join-Path $OutputPath $FileName
    & DownloadGitHubReleaseFile -RepoOwner $RepoOwner -RepoName $RepoName -TagName $TagName -FileName $FileName -OutputPath $OutputFile

    Push-Location $OutputPath
    # LIEF-0.14.1-Android-aarch64.tar.gz -> LIEF-0.14.1-Android-aarch64.tar
    & 7z x "LIEF-$($TagName)-Android-aarch64.tar.gz"
    # # LIEF-0.14.1-Android-aarch64.tar -> LIEF-0.14.1-Android-aarch64
    & 7z x "LIEF-$($TagName)-Android-aarch64.tar"

    Remove-Item -Path "LIEF-$($TagName)-Android-aarch64.tar.gz"
    Remove-Item -Path "LIEF-$($TagName)-Android-aarch64.tar"
    Pop-Location
}

$ArchDir = "armeabi-v7a"
# LIEF-0.14.1-Android-arm.tar.gz
$FileName = "$($RepoName)-$($TagName)-$($Platform)-arm.tar.gz"
if (-not (Test-Path $ArchDir)) {
    New-Item -ItemType Directory -Path $ArchDir

    $OutputPath = Join-Path $workingDir $ArchDir
    $OutputFile = Join-Path $OutputPath $FileName
    & DownloadGitHubReleaseFile -RepoOwner $RepoOwner -RepoName $RepoName -TagName $TagName -FileName $FileName -OutputPath $OutputFile

    Push-Location $OutputPath
    # LIEF-0.14.1-Android-arm.tar.gz -> LIEF-0.14.1-Android-arm.tar
    & 7z x "LIEF-$($TagName)-Android-arm.tar.gz"
    # # LIEF-0.14.1-Android-arm.tar -> LIEF-0.14.1-Android-arm
    & 7z x "LIEF-$($TagName)-Android-arm.tar"
    
    Remove-Item -Path "LIEF-$($TagName)-Android-arm.tar.gz"
    Remove-Item -Path "LIEF-$($TagName)-Android-arm.tar"
    Pop-Location
}

