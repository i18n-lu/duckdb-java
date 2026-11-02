#!/usr/bin/env bash
# ============================================================================
#  duckdb-java (含 PME 补丁) 的 Docker 一键编译脚本
# ----------------------------------------------------------------------------
#  用途：
#     使用官方 manylinux_2_28 镜像在 Docker 中编译 Linux 原生库和 JAR。
#     与 duckdb-java 官方 CI (.github/workflows/Java.yml) 的 Linux job 完全一致。
#     优点：
#       - 产物 glibc 兼容性极好 (glibc 2.28+)
#       - 构建环境可复现，不受 host 影响
#       - 可跨架构：amd64 host + QEMU 可编 arm64 产物
#
#  用法：
#     bash scripts/pme-docker-build.sh                   # 默认 amd64 release
#     ARCH=aarch64 bash scripts/pme-docker-build.sh      # arm64 (需 host 支持 QEMU)
#     BUILD_TYPE=debug bash scripts/pme-docker-build.sh
#     USE_CCACHE=1 bash scripts/pme-docker-build.sh      # 用 ccache 加速反复构建
#
#  产物位置 (host 侧)：
#     build/release/libduckdb_java.so_linux_<arch>
#     build/release/duckdb_jdbc.jar
#     build/release/duckdb_jdbc_tests.jar
#  额外归集到 dist/jdbc/，便于拷贝分发。
#
#  已知限制：
#     本脚本只能产出 Linux .so。macOS .dylib 必须在 Mac 上编，
#     Windows .dll 必须在 Windows 上编（见 scripts/pme-macos-build.sh,
#     scripts/pme-windows-build.ps1）。
# ============================================================================
set -euo pipefail

# -------- 可配置参数 --------
ARCH="${ARCH:-amd64}"                    # amd64 | aarch64
BUILD_TYPE="${BUILD_TYPE:-release}"       # release | debug
USE_CCACHE="${USE_CCACHE:-0}"             # 1 启用 ccache（host 侧 ./ccache 目录）
JOBS="${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
# ---------------------------

# 架构 -> 镜像名
case "$ARCH" in
    amd64|x86_64)
        ARCH=amd64
        IMAGE="${IMAGE:-quay.io/pypa/manylinux_2_28_x86_64}"
        PLATFORM_FLAG="--platform=linux/amd64"
        ;;
    aarch64|arm64)
        ARCH=aarch64
        IMAGE="${IMAGE:-quay.io/pypa/manylinux_2_28_aarch64}"
        PLATFORM_FLAG="--platform=linux/arm64"
        ;;
    *)
        echo "[ERR] 不支持的 ARCH=$ARCH（可选: amd64 | aarch64）"
        exit 1
        ;;
esac

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

echo "==================================================================="
echo "  duckdb-java Docker build"
echo "  ROOT       : $ROOT_DIR"
echo "  IMAGE      : $IMAGE"
echo "  ARCH       : $ARCH ($PLATFORM_FLAG)"
echo "  BUILD_TYPE : $BUILD_TYPE"
echo "  JOBS       : $JOBS"
echo "  CCACHE     : $USE_CCACHE"
echo "==================================================================="

# ---------- 1. 环境检查 ----------
command -v docker >/dev/null 2>&1 || { echo "[ERR] 未安装 docker"; exit 1; }

# 跨架构检查：如果 host 是 amd64 但要编 arm64，需要 QEMU
HOST_ARCH="$(uname -m)"
if [[ "$HOST_ARCH" == "x86_64" && "$ARCH" == "aarch64" ]] \
   || [[ "$HOST_ARCH" == "arm64" && "$ARCH" == "amd64" ]] \
   || [[ "$HOST_ARCH" == "aarch64" && "$ARCH" == "amd64" ]]; then
    echo "[INFO] 跨架构编译：host=$HOST_ARCH, target=$ARCH"
    echo "[INFO] 需要 Docker QEMU 支持；若编译报 'exec format error'，请执行一次："
    echo "       docker run --privileged --rm tonistiigi/binfmt --install all"
fi

# ---------- 2. 组装 ccache 挂载 ----------
CCACHE_MOUNT=""
CCACHE_ENV=""
if [[ "$USE_CCACHE" == "1" ]]; then
    mkdir -p "$ROOT_DIR/ccache"
    CCACHE_MOUNT="-v $ROOT_DIR/ccache:/duckdb/ccache"
    CCACHE_ENV="-e CC=ccache gcc -e CXX=ccache g++ -e CCACHE_DIR=/duckdb/ccache"
    echo "[INFO] ccache dir : $ROOT_DIR/ccache"
fi

# ---------- 3. 启动容器编译 ----------
# 挂载当前仓到容器 /duckdb；在容器里装依赖并跑 make release
# 关键环境变量：
#   GEN=ninja        -> 使用 ninja 生成器加速
#   JAVA_HOME        -> manylinux 镜像里 openjdk 的安装路径
echo "-------------------------------------------------------------------"
echo "  Running docker build..."
echo "-------------------------------------------------------------------"

docker run --rm $PLATFORM_FLAG                                       \
    -v "$ROOT_DIR":/duckdb                                           \
    -w /duckdb                                                        \
    -e GEN=ninja                                                      \
    -e JAVA_HOME=/usr/lib/jvm/java-1.8.0-openjdk                      \
    $CCACHE_MOUNT $CCACHE_ENV                                         \
    "$IMAGE"                                                          \
    bash -euxc "
        cat /etc/os-release
        dnf install -y             \
            ccache                 \
            java-1.8.0-openjdk-devel \
            ninja-build            \
            cmake                  \
            make                   \
            gcc gcc-c++
        make -j${JOBS} ${BUILD_TYPE}
    "

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
# 顺带确认一下 so 的架构
for f in "$DIST_DIR"/libduckdb_java.so_*; do
    [[ -f "$f" ]] && { echo "---- file $f ----"; file "$f" || true; }
done
echo "==================================================================="
