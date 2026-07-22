# Reproducible native Windows dependency bootstrap. Archives are verified
# before extraction and every library is compiled for the Emscripten pthread
# target. The script never invokes WSL or consumes a machine OpenSSL binary.

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Tools = Join-Path $Root ".tools"
$Version = "3.5.7"
$ArchiveName = "openssl-$Version.tar.gz"
$Archive = Join-Path $Tools "downloads/$ArchiveName"
$Source = Join-Path $Tools "sources/openssl-$Version"
$Install = Join-Path $Tools "dependencies/wasm/openssl-$Version"
$ExpectedSha256 = "a8c0d28a529ca480f9f36cf5792e2cd21984552a3c8e4aa11a24aa31aeac98e8"
$Url = "https://github.com/openssl/openssl/releases/download/openssl-$Version/$ArchiveName"
$Perl = Join-Path $env:ProgramFiles "Git/usr/bin/perl.exe"
$Emsdk = Join-Path $Tools "emsdk"
$Nghttp2Version = "1.69.0"
$Nghttp3Version = "1.17.0"
$Ngtcp2Version = "1.24.0"
$Nghttp2Install = Join-Path $Tools "dependencies/wasm/nghttp2-$Nghttp2Version"
$Nghttp3Install = Join-Path $Tools "dependencies/wasm/nghttp3-$Nghttp3Version"
$Ngtcp2Install = Join-Path $Tools "dependencies/wasm/ngtcp2-$Ngtcp2Version"

function Convert-ToMsysPath([string]$Path) {
  # OpenSSL emits configured paths into C string literals. Converting the
  # drive prefix and separators here prevents a Windows '\U' sequence from
  # becoming an invalid escape in generated C sources.
  $resolved = [System.IO.Path]::GetFullPath($Path)
  $drive = $resolved.Substring(0, 1).ToLowerInvariant()
  return "/$drive/" + $resolved.Substring(3).Replace("\", "/")
}

$OpenSslReady = (Test-Path (Join-Path $Install "lib/libcrypto.a")) -and
                (Test-Path (Join-Path $Install "lib/libssl.a"))
$Http2Ready = Test-Path (Join-Path $Nghttp2Install "lib/libnghttp2.a")
$Http3Ready = Test-Path (Join-Path $Nghttp3Install "lib/libnghttp3.a")
$QuicReady = (Test-Path (Join-Path $Ngtcp2Install "lib/libngtcp2.a")) -and
             (Test-Path (Join-Path $Ngtcp2Install "lib/libngtcp2_crypto_ossl.a"))
if ($OpenSslReady -and $Http2Ready -and $Http3Ready -and $QuicReady) {
  Write-Output "Pinned Wasm dependencies are already built"
  exit 0
}

# OpenSSL's build generator needs a Unix-path Perl and GNU Make. Git for
# Windows supplies the former. Pinned winget packages supply missing pure-Perl
# modules and Make without introducing WSL into the build.
if (-not $OpenSslReady -and
    -not (Test-Path "C:\Strawberry\perl\lib\Locale\Maketext\Simple.pm")) {
  winget install --id StrawberryPerl.StrawberryPerl --version 5.42.2.1 --exact `
    --silent --accept-package-agreements --accept-source-agreements
  if ($LASTEXITCODE -ne 0) { throw "Strawberry Perl installation failed" }
}
$Make = Get-ChildItem (Join-Path $env:LOCALAPPDATA "Microsoft/WinGet/Packages") `
  -Recurse -Filter make.exe -ErrorAction SilentlyContinue |
  Where-Object FullName -Like "*ezwinports.make*" |
  Select-Object -First 1 -ExpandProperty FullName
if (-not $OpenSslReady -and -not $Make) {
  winget install --id ezwinports.make --version 4.4.1 --exact --silent `
    --accept-package-agreements --accept-source-agreements
  if ($LASTEXITCODE -ne 0) { throw "GNU Make installation failed" }
  $Make = Get-ChildItem (Join-Path $env:LOCALAPPDATA "Microsoft/WinGet/Packages") `
    -Recurse -Filter make.exe -ErrorAction Stop |
    Where-Object FullName -Like "*ezwinports.make*" |
    Select-Object -First 1 -ExpandProperty FullName
}
if (-not $OpenSslReady -and -not (Test-Path $Perl)) {
  throw "Git for Windows Perl is required"
}
if (-not (Test-Path (Join-Path $Emsdk "emsdk_env.ps1"))) {
  throw "Run scripts/bootstrap-toolchain.ps1 before dependencies"
}

if (-not $OpenSslReady) {
  New-Item -ItemType Directory -Force (Split-Path $Archive), (Split-Path $Source) | Out-Null
  if (-not (Test-Path $Archive)) {
    Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Archive
  }
  $ActualSha256 = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
  if ($ActualSha256 -ne $ExpectedSha256) {
    throw "OpenSSL archive SHA-256 mismatch: $ActualSha256"
  }
  if (-not (Test-Path $Source)) {
    tar -xzf $Archive -C (Split-Path $Source)
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL extraction failed" }
  }

# Git Perl deliberately ships a small core. OpenSSL configure additionally
# imports these pure-Perl modules. Copying them into the ignored source tree
# avoids mixing Strawberry's Windows Config.pm with Git Perl's MSYS runtime.
  $PerlModuleRoot = Join-Path $Source "util/perl"
  Copy-Item "C:\Strawberry\perl\lib\Locale" $PerlModuleRoot -Recurse -Force
  Copy-Item "C:\Strawberry\perl\lib\ExtUtils" $PerlModuleRoot -Recurse -Force
  Copy-Item "C:\Strawberry\perl\lib\Pod" $PerlModuleRoot -Recurse -Force

  $env:EMSDK_QUIET = "1"
  . (Join-Path $Emsdk "emsdk_env.ps1")
  $env:PATH = "$(Split-Path $Perl);$(Split-Path $Make);$env:PATH"
  $env:PERL5LIB = "./util/perl"
  $env:CC = "emcc"
  $env:AR = "emar"
  $env:RANLIB = "emranlib"
  $env:CFLAGS = "-O2 -pthread"
  $MsysInstall = Convert-ToMsysPath $Install

  Push-Location $Source
  try {
    & $Perl Configure linux-generic32 no-shared no-module no-tests no-apps `
      no-ui-console no-asm no-engine no-afalgeng `
      "--prefix=$MsysInstall" "--openssldir=$MsysInstall/ssl"
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL Configure failed" }
    & $Make -j8 build_libs
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL build failed" }
    & $Make install_dev
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL development install failed" }
  } finally {
    Pop-Location
  }
  Write-Output "OpenSSL $Version Wasm dependency built and verified"
}

# Release archives contain generated CMake inputs, so no autotools or host
# shell is involved. Every archive hash comes from the corresponding official
# release checksums.txt asset. Builds contain libraries only and cannot create
# a host socket or executable that bypasses the emulator packet path.
function Get-VerifiedRelease(
    [string]$Name, [string]$ReleaseVersion, [string]$ReleaseUrl,
    [string]$ReleaseSha256) {
  $archive = Join-Path $Tools "downloads/$Name-$ReleaseVersion.tar.gz"
  $source = Join-Path $Tools "sources/$Name-$ReleaseVersion"
  New-Item -ItemType Directory -Force (Split-Path $archive),
      (Split-Path $source) | Out-Null
  if (-not (Test-Path $archive)) {
    Invoke-WebRequest -UseBasicParsing -Uri $ReleaseUrl -OutFile $archive
  }
  $actual = (Get-FileHash -Algorithm SHA256 $archive).Hash.ToLowerInvariant()
  if ($actual -ne $ReleaseSha256) {
    throw "$Name archive SHA-256 mismatch: $actual"
  }
  if (-not (Test-Path $source)) {
    tar -xzf $archive -C (Split-Path $source)
    if ($LASTEXITCODE -ne 0) { throw "$Name extraction failed" }
  }
  return $source
}

function Build-WasmCmakeLibrary(
    [string]$Name, [string]$SourcePath, [string]$InstallPath,
    [string[]]$Options) {
  $build = Join-Path $Tools "build/wasm/$Name"
  $emcmake = Join-Path $Emsdk "upstream/emscripten/emcmake.exe"
  New-Item -ItemType Directory -Force $build, $InstallPath | Out-Null
  $arguments = @("cmake", "-S", $SourcePath, "-B", $build, "-G", "Ninja",
                 "-DCMAKE_BUILD_TYPE=Release",
                 "-DCMAKE_INSTALL_PREFIX=$InstallPath",
                 "-DCMAKE_C_FLAGS=-O3 -pthread",
                 "-DCMAKE_CXX_FLAGS=-O3 -pthread") + $Options
  & $emcmake @arguments
  if ($LASTEXITCODE -ne 0) { throw "$Name CMake configure failed" }
  cmake --build $build --target install --parallel 8
  if ($LASTEXITCODE -ne 0) { throw "$Name build failed" }
}

$env:EMSDK_QUIET = "1"
. (Join-Path $Emsdk "emsdk_env.ps1")

if (-not $Http2Ready) {
  $source = Get-VerifiedRelease "nghttp2" $Nghttp2Version `
    "https://github.com/nghttp2/nghttp2/releases/download/v$Nghttp2Version/nghttp2-$Nghttp2Version.tar.gz" `
    "c866b7477cbb7512ab6863a685027adbb1bb8da8fc3bab7429ed43d3281d5aa9"
  Build-WasmCmakeLibrary "nghttp2-$Nghttp2Version" $source $Nghttp2Install @(
    "-DENABLE_LIB_ONLY=ON", "-DBUILD_SHARED_LIBS=OFF",
    "-DBUILD_STATIC_LIBS=ON", "-DBUILD_TESTING=OFF", "-DENABLE_DOC=OFF")
}

if (-not $Http3Ready) {
  $source = Get-VerifiedRelease "nghttp3" $Nghttp3Version `
    "https://github.com/ngtcp2/nghttp3/releases/download/v$Nghttp3Version/nghttp3-$Nghttp3Version.tar.gz" `
    "9635173e703174a41f9abd0d790e70562c74ec3805064403477db5a1ef94b8f5"
  Build-WasmCmakeLibrary "nghttp3-$Nghttp3Version" $source $Nghttp3Install @(
    "-DENABLE_LIB_ONLY=ON", "-DENABLE_SHARED_LIB=OFF",
    "-DENABLE_STATIC_LIB=ON", "-DBUILD_TESTING=OFF")
}

if (-not $QuicReady) {
  $source = Get-VerifiedRelease "ngtcp2" $Ngtcp2Version `
    "https://github.com/ngtcp2/ngtcp2/releases/download/v$Ngtcp2Version/ngtcp2-$Ngtcp2Version.tar.gz" `
    "be7bf725d0108cf65a43e7f439ecb7ce791fea0bbe9b51dfaa1f272903b5ef8b"
  Build-WasmCmakeLibrary "ngtcp2-$Ngtcp2Version" $source $Ngtcp2Install @(
    "-DENABLE_LIB_ONLY=ON", "-DENABLE_SHARED_LIB=OFF",
    "-DENABLE_STATIC_LIB=ON", "-DBUILD_TESTING=OFF",
    "-DENABLE_OPENSSL=ON", "-DOPENSSL_ROOT_DIR=$Install",
    "-DOPENSSL_INCLUDE_DIR=$Install/include",
    "-DOPENSSL_SSL_LIBRARY=$Install/lib/libssl.a",
    "-DOPENSSL_CRYPTO_LIBRARY=$Install/lib/libcrypto.a",
    "-DOPENSSL_USE_STATIC_LIBS=TRUE")
}

Write-Output "nghttp2 $Nghttp2Version, nghttp3 $Nghttp3Version and ngtcp2 $Ngtcp2Version Wasm dependencies built and verified"
