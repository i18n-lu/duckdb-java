#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RowGroup 按行迭代读加密 Parquet 的最小可运行示例：
  1) 生成 5w 行 x 100 列（int32 / float64 / string 各占 ~1/3）的随机数据
  2) 用 LocalKMS footer-only 加密写出，row_group_size=10000 → 恰好 5 个 row group
  3) 两种"按 row group 迭代读"的推荐姿势：
     A. ParquetFile.read_row_group(i)         —— 显式一次一组
     B. ParquetFile.iter_batches(batch_size)  —— 流式迭代，按 row group 边界出批

依赖本目录的 pyarrow_localkms.py（复用 LocalKmsClient / build_kms_connection_config）。
运行：
    python3 E_rowgroup_iter_demo.py
"""
from __future__ import annotations

import os
import string

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.parquet.encryption as pe

from pyarrow_localkms import (
    LocalKmsClient,
    build_kms_connection_config,
    FOOTER_MASTER_KEY_ID,
)

OUT_PATH = "enc_rowgroup_demo.parquet"
NUM_ROWS = 50_000
NUM_COLS = 100
ROW_GROUP_SIZE = 10_000     # → 50_000 / 10_000 = 5 个 row group
RNG = np.random.default_rng(seed=42)


# ---------- 1. 构造 5w x 100 的随机 Table ----------
def build_random_table() -> pa.Table:
    arrays, names = [], []
    # 100 列按 int / double / string 1:1:1 轮转，保证三种类型都有
    for i in range(NUM_COLS):
        kind = i % 3
        if kind == 0:
            arr = pa.array(RNG.integers(-10_000, 10_000, NUM_ROWS, dtype=np.int32))
            names.append(f"i_{i:03d}")
        elif kind == 1:
            arr = pa.array(RNG.standard_normal(NUM_ROWS).astype(np.float64))
            names.append(f"d_{i:03d}")
        else:
            # string 列：预先用 numpy 批量生成随机字母矩阵，再拼成字符串
            letters = np.array(list(string.ascii_lowercase))
            chars = RNG.choice(letters, size=(NUM_ROWS, 8))
            vals = ["".join(row) for row in chars]
            arr = pa.array(vals, type=pa.string())
            names.append(f"s_{i:03d}")
        arrays.append(arr)
    return pa.table(arrays, names=names)


# ---------- 2. footer-only 加密写入，设置 row_group_size ----------
def write_encrypted(table: pa.Table, out_path: str) -> None:
    cfg = build_kms_connection_config()
    factory = pe.CryptoFactory(lambda c: LocalKmsClient(c))

    enc_cfg = pe.EncryptionConfiguration(
        footer_key=FOOTER_MASTER_KEY_ID,
        # footer-only 风格：把所有列都挂到同一个 footer mkid 下
        column_keys={FOOTER_MASTER_KEY_ID: table.schema.names},
        encryption_algorithm="AES_GCM_V1",
        plaintext_footer=False,
        double_wrapping=False,
        internal_key_material=True,
        data_key_length_bits=256,
    )
    enc_props = factory.file_encryption_properties(cfg, enc_cfg)

    # 关键：row_group_size 控制每个 row group 的行数
    # ParquetWriter 构造函数本身不接收此参数，必须传在 write_table 上
    with pq.ParquetWriter(
        out_path,
        table.schema,
        encryption_properties=enc_props,
        compression="snappy",
    ) as w:
        w.write_table(table, row_group_size=ROW_GROUP_SIZE)

    size_mb = os.path.getsize(out_path) / 1024 / 1024
    print(f"[write] {out_path}  rows={table.num_rows} cols={table.num_columns} "
          f"size={size_mb:.2f}MB")


# ---------- 3. 按 row group 迭代读（两种姿势）----------
def iter_read_by_rowgroup(in_path: str) -> None:
    cfg = build_kms_connection_config(url="DEFAULT")
    factory = pe.CryptoFactory(lambda c: LocalKmsClient(c))
    dec_props = factory.file_decryption_properties(cfg, pe.DecryptionConfiguration())

    pf = pq.ParquetFile(in_path, decryption_properties=dec_props)
    print(f"[open] num_row_groups={pf.num_row_groups} total_rows={pf.metadata.num_rows}")

    # ---- 姿势 A：显式按下标读 row group（最直观）----
    print("\n[A] read_row_group(i):")
    total_a = 0
    for i in range(pf.num_row_groups):
        rg_table = pf.read_row_group(i)          # 一次读 1 个 row group
        total_a += rg_table.num_rows
        # 这里可以直接消费 rg_table（to_pandas / 遍历 column / 写下游等）
        print(f"  rg[{i}] rows={rg_table.num_rows} "
              f"first_i000={rg_table.column('i_000')[0].as_py()}")
    assert total_a == NUM_ROWS

    # ---- 姿势 B：iter_batches 流式迭代（更省内存，推荐用于大文件）----
    # batch_size 等于 row_group_size 时，每个 batch 恰好对应一个 row group。
    print("\n[B] iter_batches(batch_size=ROW_GROUP_SIZE):")
    total_b = 0
    for bi, batch in enumerate(pf.iter_batches(batch_size=ROW_GROUP_SIZE)):
        total_b += batch.num_rows
        print(f"  batch[{bi}] rows={batch.num_rows} "
              f"first_s002={batch.column('s_002')[0].as_py()}")
    assert total_b == NUM_ROWS

    # ---- 可选：只读部分列（投影下推）----
    print("\n[C] read_row_group(i, columns=[...])  列投影，省 I/O：")
    rg0 = pf.read_row_group(0, columns=["i_000", "d_001", "s_002"])
    print(f"  rg[0] projected schema={rg0.schema.names} rows={rg0.num_rows}")


if __name__ == "__main__":
    table = build_random_table()
    write_encrypted(table, OUT_PATH)
    iter_read_by_rowgroup(OUT_PATH)
