$root = Split-Path -Parent $PSScriptRoot

foreach ($file in Get-ChildItem -Path "$PSScriptRoot/internal/functions" -Filter *.ps1 -Recurse) {
    . $file.FullName
}

foreach ($file in Get-ChildItem -Path "$PSScriptRoot/functions" -Filter *.ps1 -Recurse) {
    . $file.FullName
}

foreach ($file in Get-ChildItem -Path "$PSScriptRoot/internal/scripts" -Filter *.ps1 -Recurse) {
    . $file.FullName
}

#load the shared internal functions
$sharedDir = Join-Path $root 'shared/EasyPIM.Shared'
foreach ($file in Get-ChildItem -Path (Join-Path $sharedDir 'internal/functions') -Filter *.ps1 -Recurse) {
	. $file.FullName
}
$orchestratorDir = Join-Path $root 'EasyPIM.Orchestrator'
foreach ($file in Get-ChildItem -Path (Join-Path $orchestratorDir 'internal/functions') -Filter *.ps1 -Recurse) {
	. $file.FullName
}
foreach ($file in Get-ChildItem -Path (Join-Path $orchestratorDir '/functions') -Filter *.ps1 -Recurse) {
	. $file.FullName
}
## Note: All internal helper functions (including Convert-IsoDuration, formerly Normalize-IsoDuration) are loaded from internal/functions/*.
