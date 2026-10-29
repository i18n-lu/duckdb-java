#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
方向 A: PyArrow(LocalKMS) 写 → DuckDB-Java(LocalKMS) 读

产物: ./enc_A.parquet（固定路径，便于反复检查文件内容）

运行:
  python3 A_pyarrow_write_duckdb_read.py
  DUCKDB_PME_JAR=/path/to/duckdb_jdbc.jar python3 A_pyarrow_write_duckdb_read.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from pyarrow_localkms import write_encrypted

HERE = Path(__file__).resolve().parent
JAVA_READER = HERE / "DuckDbReadLocalKms.java"
DEFAULT_JAR = HERE.parent.parent / "lib" / "duckdb_jdbc-1.5.4.0.jar"
OUT_PARQUET = HERE / "enc_A.parquet"


def main() -> None:
    jar = Path(os.environ.get("DUCKDB_PME_JAR") or DEFAULT_JAR)
    if not jar.is_file():
        print(f"[err] 找不到 duckdb_jdbc jar: {jar}", file=sys.stderr)
        sys.exit(2)

    parquet_path = str(OUT_PARQUET)
    if OUT_PARQUET.exists():
        OUT_PARQUET.unlink()

    print("=" * 60, "\nStep 1: PyArrow(LocalKMS) 写加密 parquet\n", "=" * 60, sep="")
    write_encrypted(parquet_path)

    print("=" * 60, "\nStep 2: DuckDB-Java(LocalKMS) 解密读\n", "=" * 60, sep="")
    subprocess.run(
        ["java", "--class-path", str(jar), str(JAVA_READER), parquet_path],
        check=True,
    )

    print(f"\n[OK] 方向 A: PyArrow → DuckDB-Java 加密互通成功 ✅")
    print(f"[OK] 产物已保存: {OUT_PARQUET}")


if __name__ == "__main__":
    main()
