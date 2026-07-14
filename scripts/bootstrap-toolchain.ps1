$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Tools = Join-Path $Root ".tools"
$PythonTools = Join-Path $Tools "python"
$Emsdk = Join-Path $Tools "emsdk"

New-Item -ItemType Directory -Force $Tools | Out-Null
python -m pip install --target $PythonTools cmake==4.4.0 ninja==1.13.0
if (-not (Test-Path $Emsdk)) {
  git clone --depth 1 https://github.com/emscripten-core/emsdk.git $Emsdk
}
& (Join-Path $Emsdk "emsdk.bat") install 6.0.3
& (Join-Path $Emsdk "emsdk.bat") activate 6.0.3
