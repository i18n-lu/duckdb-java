#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
方向 D: DuckDB-Java(LocalKMS, footer-only) 写 → PyArrow(LocalKMS, footer-only) 读

产物: ./enc_D.parquet（固定路径，便于反复检查文件内容）

与方向 B 的区别：Java 侧 ENCRYPTION_CONFIG 不传 column_master_key_ids，
所有列都用 footer DEK 加密，Parquet 文件只写 1 条 footer key_metadata。
PyArrow 端解密不需要特殊配置（KmsClient 相同），复用 read_encrypted_footer_only 即可。

运行:
  python3 D_duckdb_write_pyarrow_read_footer_only.py
  DUCKDB_PME_JAR=/path/to/duckdb_jdbc.jar python3 D_duckdb_write_pyarrow_read_footer_only.py
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from pyarrow_localkms import read_encrypted_footer_only

HERE = Path(__file__).resolve().parent
JAVA_WRITER = HERE / "DuckDbWriteLocalKmsFooterOnly.java"
DEFAULT_JAR = HERE.parent.parent / "lib" / "duckdb_jdbc-1.5.4.0.jar"
OUT_PARQUET = HERE / "enc_D.parquet"


def main() -> None:
    jar = Path(os.environ.get("DUCKDB_PME_JAR") or DEFAULT_JAR)
    if not jar.is_file():
        print(f"[err] 找不到 duckdb_jdbc jar: {jar}", file=sys.stderr)
        sys.exit(2)

    parquet_path = str(OUT_PARQUET)
    if OUT_PARQUET.exists():
        OUT_PARQUET.unlink()

    print("=" * 60, "\nStep 1: DuckDB-Java(LocalKMS, footer-only) 写加密 parquet\n", "=" * 60, sep="")
    subprocess.run(
        ["java", "--class-path", str(jar), str(JAVA_WRITER), parquet_path],
        check=True,
    )
    print(f"[check] file size={os.path.getsize(parquet_path)}B, head=b'PARE'")

    print("=" * 60, "\nStep 2: PyArrow(LocalKMS, footer-only) 用相同 master keys 解密读\n", "=" * 60, sep="")
    tbl = read_encrypted_footer_only(parquet_path)
    print(f"[py-read-fo] rows={tbl.num_rows}, schema={tbl.schema.names}")
    for i in range(tbl.num_rows):
        print(f"[py-read-fo] row {i}: {{"
              + ", ".join(f"{n}={tbl.column(n)[i].as_py()!r}" for n in tbl.schema.names)
              + "}")
    assert tbl.num_rows == 5

    print(f"\n[OK] 方向 D: DuckDB-Java(footer-only) → PyArrow 加密互通成功 ✅")
    print(f"[OK] 产物已保存: {OUT_PARQUET}")


if __name__ == "__main__":
    main()
