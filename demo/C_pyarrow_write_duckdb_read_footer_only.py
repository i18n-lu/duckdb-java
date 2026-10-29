#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
方向 C: PyArrow(LocalKMS, footer-only) 写 → DuckDB-Java(LocalKMS, footer-only) 读

产物: ./enc_C.parquet（固定路径，便于反复检查文件内容）

与方向 A 的区别：PyArrow EncryptionConfiguration 不传 column_keys，
所有列都用 footer DEK 加密，Parquet 文件只写 1 条 footer key_metadata。
Java 端用 DuckDbReadLocalKmsFooterOnly（encryption_config 只带 footer_master_key_id）。

运行:
  python3 C_pyarrow_write_duckdb_read_footer_only.py
  DUCKDB_PME_JAR=/path/to/duckdb_jdbc.jar python3 C_pyarrow_write_duckdb_read_footer_only.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from pyarrow_localkms import write_encrypted_footer_only

HERE = Path(__file__).resolve().parent
JAVA_READER = HERE / "DuckDbReadLocalKmsFooterOnly.java"
DEFAULT_JAR = HERE.parent.parent / "lib" / "duckdb_jdbc-1.5.4.0.jar"
OUT_PARQUET = HERE / "enc_C.parquet"


def main() -> None:
    jar = Path(os.environ.get("DUCKDB_PME_JAR") or DEFAULT_JAR)
    if not jar.is_file():
        print(f"[err] 找不到 duckdb_jdbc jar: {jar}", file=sys.stderr)
        sys.exit(2)

    parquet_path = str(OUT_PARQUET)
    if OUT_PARQUET.exists():
        OUT_PARQUET.unlink()

    print("=" * 60, "\nStep 1: PyArrow(LocalKMS, footer-only) 写加密 parquet\n", "=" * 60, sep="")
    write_encrypted_footer_only(parquet_path)

    print("=" * 60, "\nStep 2: DuckDB-Java(LocalKMS, footer-only) 解密读\n", "=" * 60, sep="")
    subprocess.run(
        ["java", "--class-path", str(jar), str(JAVA_READER), parquet_path],
        check=True,
    )

    print(f"\n[OK] 方向 C: PyArrow(footer-only) → DuckDB-Java 加密互通成功 ✅")
    print(f"[OK] 产物已保存: {OUT_PARQUET}")


if __name__ == "__main__":
    main()
