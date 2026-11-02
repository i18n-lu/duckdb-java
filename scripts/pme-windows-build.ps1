# ============================================================================
#  duckdb-java (含 PME 补丁) 的 Windows 一键编译脚本 (PowerShell)
# ----------------------------------------------------------------------------
#  用法 (在 "x64 Native Tools Command Prompt for VS 2022" 或已配置 MSVC 的 PowerShell 里)：
#     powershell -ExecutionPolicy Bypass -File scripts\pme-windows-build.ps1
#     powershell -ExecutionPolicy Bypass -File scripts\pme-windows-build.ps1 -BuildType debug
#     powershell -ExecutionPolicy Bypass -File scripts\pme-windows-build.ps1 -Arch ARM64
#     powershell -ExecutionPolicy Bypass -File scripts\pme-windows-build.ps1 -Generator "Visual Studio 16 2019"
#
#  产物位置：
#     build\release\Release\libduckdb_java.dll_windows_amd64    # JNI 原生库
#     build\release\duckdb_jdbc.jar                              # JDBC 驱动（已内嵌 .dll）
#     build\release\duckdb_jdbc_tests.jar                        # 测试用例
#
#  同时会把上述文件 **复制一份到 dist\jdbc\** 方便拷贝分发。
# ============================================================================
[CmdletBinding()]
param(
    [ValidateSet('release','debug')]
    [string]$BuildType = 'release',
    [string]$Generator = 'Visual Studio 17 2022',
    [ValidateSet('x64','Win32','ARM64')]
    [string]$Arch      = 'x64',
    [int]   $Jobs      = [Environment]::ProcessorCount
)

$ErrorActionPreference = 'Stop'

# -------- 路径准备 --------
$RootDir = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $RootDir

$CfgName = if ($BuildType -eq 'release') { 'Release' } else { 'Debug' }
$BuildDir = Join-Path $RootDir ("build\" + $BuildType)
$DistDir  = Join-Path $RootDir 'dist\jdbc'

Write-Host "==================================================================="
Write-Host "  duckdb-java Windows build"
Write-Host "  ROOT       : $RootDir"
Write-Host "  BUILD_TYPE : $BuildType ($CfgName)"
Write-Host "  Generator  : $Generator"
Write-Host "  Arch       : $Arch"
Write-Host "  Jobs       : $Jobs"
Write-Host "==================================================================="

# ---------- 1. 基础环境检查 ----------
function Assert-Cmd($name, $hint) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Write-Error "[ERR] 未找到 $name。$hint"
        exit 1
    }
}
Assert-Cmd 'cmake' '请安装 CMake >= 3.11 并加入 PATH'
Assert-Cmd 'javac' '请安装 JDK (推荐 Microsoft OpenJDK 17) 并设置 JAVA_HOME / PATH'

if (-not $env:JAVA_HOME -or -not (Test-Path $env:JAVA_HOME)) {
    # 从 javac 位置反推
    $javacPath = (Get-Command javac).Source
    $jh = Split-Path (Split-Path $javacPath -Parent) -Parent
    if (Test-Path $jh) {
        $env:JAVA_HOME = $jh
        Write-Host "[INFO] 自动设置 JAVA_HOME=$jh"
    } else {
        Write-Error "[ERR] 请手动设置 JAVA_HOME"
        exit 1
    }
}

Write-Host "[INFO] JAVA_HOME = $env:JAVA_HOME"
Write-Host "[INFO] cmake   : $((cmake --version | Select-Object -First 1))"
Write-Host "[INFO] java    : $((& java -version 2>&1 | Select-Object -First 1))"

# ---------- 2. 配置并编译 ----------
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}

Write-Host "-------------------------------------------------------------------"
Write-Host "  cmake configure"
Write-Host "-------------------------------------------------------------------"
& cmake -S $RootDir -B $BuildDir -G $Generator -A $Arch -DCMAKE_BUILD_TYPE=$CfgName
if ($LASTEXITCODE -ne 0) { Write-Error "cmake 配置失败"; exit 1 }

Write-Host "-------------------------------------------------------------------"
Write-Host "  cmake build ($CfgName)"
Write-Host "-------------------------------------------------------------------"
& cmake --build $BuildDir --config $CfgName --parallel $Jobs
if ($LASTEXITCODE -ne 0) { Write-Error "编译失败"; exit 1 }

# ---------- 3. 归集产物 ----------
if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
}

Write-Host "-------------------------------------------------------------------"
Write-Host "  Collecting artifacts to $DistDir"
Write-Host "-------------------------------------------------------------------"

# Windows 多配置生成器会把 dll 放到 Release/ 子目录；jar 由 Makefile 规则生成在 build 根下
$candidates = @(
    (Join-Path $BuildDir "$CfgName\libduckdb_java.dll_*"),
    (Join-Path $BuildDir "$CfgName\libduckdb_java.so_windows_*"),
    (Join-Path $BuildDir 'duckdb_jdbc.jar'),
    (Join-Path $BuildDir 'duckdb_jdbc_tests.jar')
)

$copied = 0
foreach ($pattern in $candidates) {
    Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $DistDir -Force
        Write-Host "  copied: $($_.Name)"
        $copied++
    }
}

if ($copied -eq 0) {
    Write-Error "[ERR] 没有找到构建产物，请检查上面的编译输出"
    exit 1
}

Write-Host "==================================================================="
Write-Host "  Build DONE. Artifacts:"
Get-ChildItem $DistDir | Format-Table Name, Length, LastWriteTime
Write-Host "==================================================================="
