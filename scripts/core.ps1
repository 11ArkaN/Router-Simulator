# Native Windows entry point for the pinned Emscripten build, tests, benchmarks
# and browser artifact publication. It never enters or depends on WSL.

param(
  [ValidateSet("build", "test", "manual", "benchmark", "structure-benchmark", "runtime-benchmark", "publish")]
  [string]$Task = "build"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Emsdk = Join-Path $Root ".tools/emsdk"
$CmakeBin = Join-Path $Root ".tools/python/cmake/data/bin"
$NinjaBin = Join-Path $Root ".tools/python/bin"
$Build = Join-Path $Root "build/wasm"

if (-not (Test-Path (Join-Path $Emsdk "emsdk_env.ps1"))) {
  throw "Local Emscripten toolchain is missing. Run the toolchain bootstrap described in README.md."
}

$env:EMSDK_QUIET = "1"
# emsdk_env.ps1 creates and removes one fixed emsdk_set_env.ps1 file. Parallel
# benchmark or CI invocations would race on that file and fail before CMake.
# A machine-local mutex serializes only environment construction; builds still
# run concurrently after every process has received its private environment.
$EmsdkMutex = [System.Threading.Mutex]::new($false, "Local\RouterSimulatorEmsdkEnv")
try {
  $EmsdkMutex.WaitOne() | Out-Null
  . (Join-Path $Emsdk "emsdk_env.ps1")
} finally {
  $EmsdkMutex.ReleaseMutex()
  $EmsdkMutex.Dispose()
}
$env:PATH = "$CmakeBin;$NinjaBin;$env:PATH"

if (-not (Test-Path (Join-Path $Build "build.ninja"))) {
  # Configure once with the repository-local native Windows toolchain. CMake
  # reruns itself automatically when profile or build inputs change.
  emcmake cmake -S (Join-Path $Root "core") -B $Build -G Ninja
}

cmake --build $Build
if ($LASTEXITCODE -ne 0) { throw "Core build failed." }

switch ($Task) {
  # Each task consumes the same fully built graph, preventing manual and
  # benchmark executables from testing different compile flags than production.
  "test" {
    node (Join-Path $Build "module_tests.js")
    if ($LASTEXITCODE -eq 0) { node (Join-Path $Build "core_tests.js") }
  }
  "manual" { node (Join-Path $Build "manual_session.js") }
  "benchmark" { node (Join-Path $Build "packet_benchmark.js") }
  "structure-benchmark" { node (Join-Path $Build "structure_benchmark.js") }
  "runtime-benchmark" { node (Join-Path $Build "runtime_benchmark.js") }
  "publish" {
    $Output = Join-Path $Root "apps/web/public/wasm"
    New-Item -ItemType Directory -Force $Output | Out-Null
    Copy-Item (Join-Path $Build "simulator.js") $Output -Force
    Copy-Item (Join-Path $Build "simulator.wasm") $Output -Force
  }
}

# PowerShell does not automatically turn a failed native child process into a
# failed script. Propagating Node's exit status prevents CI from reporting green
# after a Wasm trap, failed assertion, sanitizer abort, or benchmark crash.
if ($Task -in @("test", "manual", "benchmark", "structure-benchmark", "runtime-benchmark") -and $LASTEXITCODE -ne 0) {
  throw "Core $Task executable failed with exit code $LASTEXITCODE."
}
