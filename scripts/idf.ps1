# Runs idf.py for one firmware project with ESP-IDF exported.
#   .\scripts\idf.ps1 door build
#   .\scripts\idf.ps1 door -p COM5 flash monitor
param(
    [Parameter(Mandatory = $true)][ValidateSet("door", "panel")][string]$Project,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$IdfArgs
)
$ErrorActionPreference = "Continue"
$idf = if ($env:IDF_PATH) { $env:IDF_PATH } else { "C:\esp\esp-idf" }
. "$idf\export.ps1" | Out-Null
$root = Split-Path -Parent $PSScriptRoot
idf.py -C (Join-Path $root "firmware\$Project") @IdfArgs
exit $LASTEXITCODE
