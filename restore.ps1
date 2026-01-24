# 用途: 恢复被修改的 native 库到原始状态
# 功能: 调用 modify.ps1 的恢复模式，将备份的 so 文件恢复
# 用法: .\restore.ps1 [-ApkName "包名"]

param (
    [string]$ApkName = "com.jywsqk.jh.jh"
)

if ([string]::IsNullOrWhiteSpace($ApkName)) {
    Write-Host "Usage: restore.ps1 [-ApkName <package_name>]" -ForegroundColor Yellow
    exit 0
}

Write-Host "Restoring library for $ApkName..." -ForegroundColor Cyan

& "$PSScriptRoot\modify.ps1" -ApkName $ApkName -restore $True
