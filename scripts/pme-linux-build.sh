#!/usr/bin/env bash
# ============================================================================
#  duckdb-java (含 PME 补丁) 的 Linux 一键编译脚本
# ----------------------------------------------------------------------------
#  用法：
#     bash scripts/pme-linux-build.sh                 # 默认 release
#     BUILD_TYPE=debug bash scripts/pme-linux-build.sh
#     JOBS=16 bash scripts/pme-linux-build.sh
#
#  产物位置：
#     build/release/libduckdb_java.so_linux_<arch>    # JNI 原生库
#     build/release/duckdb_jdbc.jar                   # JDBC 驱动（已内嵌 .so）
#     build/release/duckdb_jdbc_tests.jar             # 测试用例
#
#  同时会把上述文件 **复制一份到 dist/jdbc/** 方便 scp 回取。
# ============================================================================
set -euo pipefail

# -------- 可配置参数 --------
BUILD_TYPE="${BUILD_TYPE:-release}"           # release | debug
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
GEN="${GEN:-}"                                # ninja（可选，加速）
# ---------------------------

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "==================================================================="
echo "  duckdb-java Linux build"
echo "  ROOT       : $ROOT_DIR"
echo "  BUILD_TYPE : $BUILD_TYPE"
echo "  JOBS       : $JOBS"
echo "  GEN        : ${GEN:-<make>}"
echo "==================================================================="

# ---------- 1. 基础环境检查 ----------
command -v gcc    >/dev/null 2>&1 || { echo "[ERR] gcc 未安装"; exit 1; }
command -v g++    >/dev/null 2>&1 || { echo "[ERR] g++ 未安装"; exit 1; }
command -v cmake  >/dev/null 2>&1 || { echo "[ERR] cmake 未安装"; exit 1; }
command -v make   >/dev/null 2>&1 || { echo "[ERR] make 未安装"; exit 1; }
command -v javac  >/dev/null 2>&1 || { echo "[ERR] javac 未安装（需要 JDK，并设置 JAVA_HOME）"; exit 1; }

if [[ -z "${JAVA_HOME:-}" ]]; then
    # 尝试自动探测
    JH="$(readlink -f "$(command -v javac)" 2>/dev/null | sed 's#/bin/javac##')"
    if [[ -n "$JH" && -d "$JH" ]]; then
        export JAVA_HOME="$JH"
        echo "[INFO] 自动设置 JAVA_HOME=$JAVA_HOME"
    else
        echo "[ERR] 请手动设置 JAVA_HOME"
        exit 1
    fi
fi

echo "[INFO] JAVA_HOME = $JAVA_HOME"
echo "[INFO] gcc 版本  : $(gcc --version | head -1)"
echo "[INFO] cmake版本 : $(cmake --version | head -1)"
echo "[INFO] java 版本 : $(java -version 2>&1 | head -1)"

# ---------- 2. ninja 可选加速 ----------
GENERATOR_ARG=""
if [[ "$GEN" == "ninja" ]]; then
    command -v ninja >/dev/null 2>&1 || { echo "[ERR] 指定 GEN=ninja 但未安装 ninja"; exit 1; }
    GENERATOR_ARG='-G Ninja'
fi

# ---------- 3. 执行编译 ----------
echo "-------------------------------------------------------------------"
echo "  Running: make $BUILD_TYPE"
echo "-------------------------------------------------------------------"
if [[ -n "$GENERATOR_ARG" ]]; then
    GEN=ninja make -j"$JOBS" "$BUILD_TYPE"
else
    make -j"$JOBS" "$BUILD_TYPE"
fi

# ---------- 4. 归集产物 ----------
OUT_DIR="build/$BUILD_TYPE"
DIST_DIR="dist/jdbc"
mkdir -p "$DIST_DIR"

echo "-------------------------------------------------------------------"
echo "  Collecting artifacts to $DIST_DIR/"
echo "-------------------------------------------------------------------"

shopt -s nullglob
copied=0
for f in "$OUT_DIR"/libduckdb_java.so_* \
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
echo "==================================================================="
