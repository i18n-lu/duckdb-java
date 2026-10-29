#!/usr/bin/env bash
# ----------------------------------------------------------------------------
# demo/run_demos.sh — 一键跑完 demo 下 5 个样例（JDK 1.8 + Python3.9 + pyarrow 17）
#
# 用途：
#   * 固定 JAVA_HOME 到 JDK 1.8（jdk1.8.0_462），验证已编译的 .class 在 1.8 下跑通
#   * 固定 DUCKDB_PME_JAR 到 demo/lib 下的 jar（修复入口脚本中错误的默认路径）
#   * 用 demo/bin/java wrapper 劫持 `java FooBar.java` 风格的 JDK 11+ 语法
#
# 使用：
#   bash demo/run_demos.sh            # 跑全部 5 个样例
#   bash demo/run_demos.sh A C E      # 只跑指定几个
# ----------------------------------------------------------------------------
set -eo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLASSES_DIR="$DEMO_DIR/classes"
JAR="$DEMO_DIR/lib/duckdb_jdbc-1.5.4.0.jar"
JDK18_HOME="/Library/Java/JavaVirtualMachines/jdk1.8.0_462.jdk/Contents/Home"

# -------- 1. 预检 --------
[[ -d "$JDK18_HOME" ]] || { echo "[err] JDK 1.8 not found: $JDK18_HOME" >&2; exit 2; }
[[ -f "$JAR" ]]        || { echo "[err] jar not found: $JAR" >&2; exit 2; }

# -------- 2. 必要时自动编译 Java --------
need_compile=0
for cls in DuckDbReadLocalKms DuckDbReadLocalKmsFooterOnly DuckDbWriteLocalKms DuckDbWriteLocalKmsFooterOnly; do
    [[ -f "$CLASSES_DIR/$cls.class" ]] || need_compile=1
done
if [[ $need_compile -eq 1 ]]; then
    echo "[build] 用 JDK 1.8 编译 Java demo 到 $CLASSES_DIR"
    mkdir -p "$CLASSES_DIR"
    "$JDK18_HOME/bin/javac" -source 1.8 -target 1.8 -cp "$JAR" -d "$CLASSES_DIR" \
        "$DEMO_DIR"/DuckDbReadLocalKms.java \
        "$DEMO_DIR"/DuckDbReadLocalKmsFooterOnly.java \
        "$DEMO_DIR"/DuckDbWriteLocalKms.java \
        "$DEMO_DIR"/DuckDbWriteLocalKmsFooterOnly.java
fi

# -------- 3. 组装环境：PATH 优先用 wrapper，再接 JDK 1.8，再接系统 PATH --------
export JAVA_HOME="$JDK18_HOME"
export REAL_JAVA="$JDK18_HOME/bin/java"
export PATH="$DEMO_DIR/bin:$JDK18_HOME/bin:$PATH"
export DUCKDB_PME_JAR="$JAR"

echo "[env] JAVA_HOME=$JAVA_HOME"
echo "[env] DUCKDB_PME_JAR=$DUCKDB_PME_JAR"
echo "[env] java -version:"
java -version 2>&1 | sed 's/^/       /'
echo "[env] python3: $(python3 --version)   pyarrow: $(python3 -c 'import pyarrow,sys; sys.stdout.write(pyarrow.__version__)')"
echo

# -------- 4. 选择要跑的样例 --------
script_for() {
    case "$1" in
        A) echo "A_pyarrow_write_duckdb_read.py" ;;
        B) echo "B_duckdb_write_pyarrow_read.py" ;;
        C) echo "C_pyarrow_write_duckdb_read_footer_only.py" ;;
        D) echo "D_duckdb_write_pyarrow_read_footer_only.py" ;;
        E) echo "E_rowgroup_iter_demo.py" ;;
        *) echo "" ;;
    esac
}

if [[ $# -gt 0 ]]; then
    TARGETS=("$@")
else
    TARGETS=(A B C D E)
fi

cd "$DEMO_DIR"

FAIL_COUNT=0
PASS_COUNT=0
for t in "${TARGETS[@]}"; do
    script="$(script_for "$t")"
    if [[ -z "$script" ]]; then
        echo "[skip] 未知样例: $t" >&2
        continue
    fi
    echo "============================================================"
    echo "[run] $t -> $script"
    echo "============================================================"
    if python3 "$script"; then
        PASS_COUNT=$((PASS_COUNT+1))
        echo "[pass] $t ✅"
    else
        FAIL_COUNT=$((FAIL_COUNT+1))
        echo "[fail] $t ❌" >&2
    fi
    echo
done

echo "============================================================"
echo "[summary] 通过 $PASS_COUNT 个，失败 $FAIL_COUNT 个"
echo "============================================================"

[[ $FAIL_COUNT -eq 0 ]] || exit 1
