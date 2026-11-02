#!/usr/bin/env bash
# ============================================================================
#  duckdb-java (含 PME 补丁) 的 macOS 一键编译脚本
# ----------------------------------------------------------------------------
#  用法：
#     bash scripts/pme-macos-build.sh                 # 默认 release，Universal (x86_64+arm64)
#     BUILD_TYPE=debug bash scripts/pme-macos-build.sh
#     JOBS=16 bash scripts/pme-macos-build.sh
#     OSX_ARCH=arm64  bash scripts/pme-macos-build.sh # 单架构，只打当前 CPU
#     OSX_ARCH=x86_64 bash scripts/pme-macos-build.sh
#
#  产物位置：
#     build/release/libduckdb_java.dylib_osx_universal   # JNI 原生库
#     build/release/duckdb_jdbc.jar                      # JDBC 驱动（已内嵌 .dylib）
#     build/release/duckdb_jdbc_tests.jar                # 测试用例
#
#  同时会把上述文件 **复制一份到 dist/jdbc/** 方便 scp 回取。
# ============================================================================
set -euo pipefail

# -------- 可配置参数 --------
BUILD_TYPE="${BUILD_TYPE:-release}"           # release | debug
JOBS="${JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
GEN="${GEN:-}"                                # ninja（可选，加速）
OSX_ARCH="${OSX_ARCH:-}"                      # 空=工程默认(Universal)；可填 arm64 / x86_64
# ---------------------------

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "==================================================================="
echo "  duckdb-java macOS build"
echo "  ROOT       : $ROOT_DIR"
echo "  BUILD_TYPE : $BUILD_TYPE"
echo "  JOBS       : $JOBS"
echo "  GEN        : ${GEN:-<make>}"
echo "  OSX_ARCH   : ${OSX_ARCH:-<universal(default)>}"
echo "==================================================================="

# ---------- 1. 基础环境检查 ----------
if ! xcode-select -p >/dev/null 2>&1; then
    echo "[ERR] 未检测到 Xcode Command Line Tools，请先执行: xcode-select --install"
    exit 1
fi
command -v clang  >/dev/null 2>&1 || { echo "[ERR] clang 未安装"; exit 1; }
command -v cmake  >/dev/null 2>&1 || { echo "[ERR] cmake 未安装（brew install cmake）"; exit 1; }
command -v make   >/dev/null 2>&1 || { echo "[ERR] make 未安装"; exit 1; }
command -v javac  >/dev/null 2>&1 || { echo "[ERR] javac 未安装（brew install openjdk@17 并设置 JAVA_HOME）"; exit 1; }

if [[ -z "${JAVA_HOME:-}" ]]; then
    # macOS 推荐用 /usr/libexec/java_home 探测
    if command -v /usr/libexec/java_home >/dev/null 2>&1; then
        JH="$(/usr/libexec/java_home 2>/dev/null || true)"
    fi
    if [[ -z "${JH:-}" || ! -d "${JH:-}" ]]; then
        JH="$(dirname "$(dirname "$(readlink "$(command -v javac)" || command -v javac)")")"
    fi
    if [[ -n "$JH" && -d "$JH" ]]; then
        export JAVA_HOME="$JH"
        echo "[INFO] 自动设置 JAVA_HOME=$JAVA_HOME"
    else
        echo "[ERR] 请手动设置 JAVA_HOME"
        exit 1
    fi
fi

echo "[INFO] JAVA_HOME = $JAVA_HOME"
echo "[INFO] clang 版本 : $(clang --version | head -1)"
echo "[INFO] cmake 版本 : $(cmake --version | head -1)"
echo "[INFO] java  版本 : $(java -version 2>&1 | head -1)"

# ---------- 1.5 修复 Command Line Tools 的 libc++ 头文件缺失 ----------
# 某些 macOS 下 CLT 的 /Library/Developer/CommandLineTools/usr/include/c++/v1
# 目录只保留了内部头（__memory/__functional/...），缺失 <memory>/<string>/<sstream>
# 等标准头文件，而 SDK 下的 c++/v1 是完整的。
# 这里探测该情况并通过 CPATH 自动把 SDK 的 c++/v1 加入 clang 搜索路径。
SDK_PATH="$(xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)"
if [[ -n "$SDK_PATH" ]]; then
    CLT_CXX_DIR="/Library/Developer/CommandLineTools/usr/include/c++/v1"
    SDK_CXX_DIR="$SDK_PATH/usr/include/c++/v1"
    # 判定：CLT 侧 <memory> 不存在，但 SDK 侧有，就补一下
    if [[ ! -f "$CLT_CXX_DIR/memory" && -f "$SDK_CXX_DIR/memory" ]]; then
        echo "[WARN] 检测到 CLT 的 libc++ 伞形头文件不完整 ($CLT_CXX_DIR/memory 缺失)"
        echo "[INFO] 自动将 $SDK_CXX_DIR 加入 CPATH / CPLUS_INCLUDE_PATH"
        export CPATH="$SDK_CXX_DIR${CPATH:+:$CPATH}"
        export CPLUS_INCLUDE_PATH="$SDK_CXX_DIR${CPLUS_INCLUDE_PATH:+:$CPLUS_INCLUDE_PATH}"
    fi
fi

# ---------- 2. 架构覆写（可选） ----------
# 工程 CMakeLists.txt 默认 CMAKE_OSX_ARCHITECTURES="x86_64;arm64"（Universal）。
# 如用户指定 OSX_ARCH，则通过 CMAKE_ARGS 覆写，Makefile 会把它传给 cmake。
if [[ -n "$OSX_ARCH" ]]; then
    export CMAKE_ARGS="${CMAKE_ARGS:-} -DCMAKE_OSX_ARCHITECTURES=${OSX_ARCH}"
    echo "[INFO] 覆写 OSX 架构: $OSX_ARCH"
fi

# ---------- 3. ninja 可选加速 ----------
if [[ "$GEN" == "ninja" ]]; then
    command -v ninja >/dev/null 2>&1 || { echo "[ERR] 指定 GEN=ninja 但未安装 ninja（brew install ninja）"; exit 1; }
fi

# ---------- 4. 执行编译 ----------
echo "-------------------------------------------------------------------"
echo "  Running: make $BUILD_TYPE"
echo "-------------------------------------------------------------------"
if [[ "$GEN" == "ninja" ]]; then
    GEN=ninja make -j"$JOBS" "$BUILD_TYPE"
else
    make -j"$JOBS" "$BUILD_TYPE"
fi

# ---------- 5. 归集产物 ----------
OUT_DIR="build/$BUILD_TYPE"
DIST_DIR="dist/jdbc"
mkdir -p "$DIST_DIR"

echo "-------------------------------------------------------------------"
echo "  Collecting artifacts to $DIST_DIR/"
echo "-------------------------------------------------------------------"

shopt -s nullglob
copied=0
# 注意：duckdb-java 的 CMake 在所有平台都用 .so_ 前缀命名 native lib，
# macOS 的产物是 libduckdb_java.so_osx_universal（Mach-O Universal 二进制），
# 不是 .dylib。这里两种 glob 都兼顾一下。
for f in "$OUT_DIR"/libduckdb_java.so_osx_* \
         "$OUT_DIR"/libduckdb_java.dylib_* \
         "$OUT_DIR"/duckdb_jdbc.jar \
         "$OUT_DIR"/duckdb_jdbc_tests.jar; do
    if [[ -f "$f" ]]; then
        cp -v "$f" "$DIST_DIR/"
        copied=$((copied+1))
    fi
done

if [[ $copied -eq 0 ]]; then
    echo "[ERR] 没有找到构建产物，请检查上面的编译输出"
    exit 1
fi

echo "==================================================================="
echo "  Build DONE. Artifacts:"
ls -lh "$DIST_DIR/"
# 顺带校验一下 Universal 架构（如适用）
for d in "$DIST_DIR"/libduckdb_java.so_osx_* "$DIST_DIR"/libduckdb_java.dylib_*; do
    [[ -f "$d" ]] && { echo "---- lipo -info $d ----"; lipo -info "$d" || true; }
done
echo "==================================================================="
