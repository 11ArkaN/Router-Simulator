# Idempotent native Windows toolchain bootstrap. Downloads are pinned and kept
# under .toolchain so the repository does not depend on machine-wide WSL tools.

$ErrorActionPreference = "Stop"
# Resolve every dependency below the repository so native Windows builds do not
# depend on WSL, global CMake, global Ninja or a user-specific SDK installation.
$Root = Split-Path -Parent $PSScriptRoot
$Tools = Join-Path $Root ".tools"
$PythonTools = Join-Path $Tools "python"
$Emsdk = Join-Path $Tools "emsdk"

New-Item -ItemType Directory -Force $Tools | Out-Null
# Pinned package versions make local and CI generator behavior reproducible.
python -m pip install --target $PythonTools cmake==4.4.0 ninja==1.13.0
if (-not (Test-Path $Emsdk)) {
  # Clone only when absent so rerunning bootstrap preserves the local SDK cache.
  git clone --depth 1 https://github.com/emscripten-core/emsdk.git $Emsdk
}
# Install and activate the same Emscripten version referenced by source records.
& (Join-Path $Emsdk "emsdk.bat") install 6.0.3
& (Join-Path $Emsdk "emsdk.bat") activate 6.0.3
