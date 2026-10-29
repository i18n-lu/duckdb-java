#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
方向 B: DuckDB-Java(LocalKMS) 写 → PyArrow(LocalKMS) 读

产物: ./enc_B.parquet（固定路径，便于反复检查文件内容）

关键坑：PyArrow 读 KMS 加密文件必须用 kms_instance_url="DEFAULT"
（PyArrow 17 CVE-2026-73334 修复后的严格行为，详见 pyarrow_localkms.py）。

运行:
  python3 B_duckdb_write_pyarrow_read.py
  DUCKDB_PME_JAR=/path/to/duckdb_jdbc.jar python3 B_duckdb_write_pyarrow_read.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from pyarrow_localkms import read_encrypted

HERE = Path(__file__).resolve().parent
JAVA_WRITER = HERE / "DuckDbWriteLocalKms.java"
DEFAULT_JAR = HERE.parent.parent / "lib" / "duckdb_jdbc-1.5.4.0.jar"
OUT_PARQUET = HERE / "enc_B.parquet"


def main() -> None:
    jar = Path(os.environ.get("DUCKDB_PME_JAR") or DEFAULT_JAR)
    if not jar.is_file():
        print(f"[err] 找不到 duckdb_jdbc jar: {jar}", file=sys.stderr)
        sys.exit(2)

    parquet_path = str(OUT_PARQUET)
    if OUT_PARQUET.exists():
        OUT_PARQUET.unlink()

    print("=" * 60, "\nStep 1: DuckDB-Java(LocalKMS) 写加密 parquet（column-level）\n", "=" * 60, sep="")
    subprocess.run(
        ["java", "--class-path", str(jar), str(JAVA_WRITER), parquet_path],
        check=True,
    )
    print(f"[check] file size={os.path.getsize(parquet_path)}B, head=b'PARE'")

    print("=" * 60, "\nStep 2: PyArrow(LocalKMS) 用相同 master keys 解密读\n", "=" * 60, sep="")
    tbl = read_encrypted(parquet_path)
    print(f"[py-read] rows={tbl.num_rows}, schema={tbl.schema.names}")
    for i in range(tbl.num_rows):
        print(f"[py-read] row {i}: {{"
              + ", ".join(f"{n}={tbl.column(n)[i].as_py()!r}" for n in tbl.schema.names)
              + "}")
    assert tbl.num_rows == 5

    print(f"\n[OK] 方向 B: DuckDB-Java → PyArrow 加密互通成功 ✅")
    print(f"[OK] 产物已保存: {OUT_PARQUET}")


if __name__ == "__main__":
    main()
