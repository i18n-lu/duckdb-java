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


# ---------- 4. 边界校验：证明每组确实是 [i*1w, (i+1)*1w) 这段 ----------
def verify_rowgroup_boundary(in_path: str, origin: pa.Table) -> None:
    """用 4 条独立证据链证明 row group 边界正确、无重复、无遗漏、顺序不乱。

    证据：
      ① 元数据层：pf.metadata.row_group(i).num_rows 累加 == 原表行数，且逐组 == 1w
      ② 首尾比对：第 i 组首行 == origin[i*1w]、末行 == origin[(i+1)*1w - 1]
      ③ 整组比对：rg_table.equals(origin.slice(i*1w, 1w)) 为 True
      ④ 拼接比对：concat(所有组) 与整体 read_table 结果完全一致
    """
    cfg = build_kms_connection_config(url="DEFAULT")
    factory = pe.CryptoFactory(lambda c: LocalKmsClient(c))
    dec_props = factory.file_decryption_properties(cfg, pe.DecryptionConfiguration())
    pf = pq.ParquetFile(in_path, decryption_properties=dec_props)

    print("\n========== 边界校验 ==========")

    # ---- ① 元数据层（不解密数据，纯读 footer 元信息）----
    print("\n[①] 元数据层 RowGroupMetaData.num_rows（不解密 column data）：")
    meta_total = 0
    for i in range(pf.num_row_groups):
        n = pf.metadata.row_group(i).num_rows
        meta_total += n
        assert n == ROW_GROUP_SIZE, f"rg[{i}] 元数据行数={n}，期望={ROW_GROUP_SIZE}"
        print(f"  rg[{i}].num_rows = {n}  ✓")
    assert meta_total == origin.num_rows, \
        f"元数据累加行数={meta_total}，期望={origin.num_rows}"
    print(f"  累加 {meta_total} == 原表 {origin.num_rows}  ✓")

    # ---- ② 首尾比对：抽样证明"起点"和"终点"都对（最直观）----
    print("\n[②] 每组首行 / 末行 vs 原表切片首行 / 末行（抽样 i_000、s_002）：")
    for i in range(pf.num_row_groups):
        rg = pf.read_row_group(i)
        lo, hi = i * ROW_GROUP_SIZE, (i + 1) * ROW_GROUP_SIZE - 1

        rg_first_i = rg.column("i_000")[0].as_py()
        rg_last_i  = rg.column("i_000")[-1].as_py()
        rg_first_s = rg.column("s_002")[0].as_py()
        rg_last_s  = rg.column("s_002")[-1].as_py()

        og_first_i = origin.column("i_000")[lo].as_py()
        og_last_i  = origin.column("i_000")[hi].as_py()
        og_first_s = origin.column("s_002")[lo].as_py()
        og_last_s  = origin.column("s_002")[hi].as_py()

        assert rg_first_i == og_first_i and rg_last_i == og_last_i, \
            f"rg[{i}] i_000 边界不匹配"
        assert rg_first_s == og_first_s and rg_last_s == og_last_s, \
            f"rg[{i}] s_002 边界不匹配"
        print(f"  rg[{i}]  i_000[0]={rg_first_i}=={og_first_i}@origin[{lo}]  "
              f"i_000[-1]={rg_last_i}=={og_last_i}@origin[{hi}]  "
              f"s_002[0]='{rg_first_s}'  s_002[-1]='{rg_last_s}'  ✓")

    # ---- ③ 整组逐行比对：100 列 x 1w 行 全部一致（内容 + 顺序双重保证）----
    print("\n[③] 每组整组 rg.equals(origin.slice(i*1w, 1w))：")
    for i in range(pf.num_row_groups):
        rg = pf.read_row_group(i)
        slice_i = origin.slice(i * ROW_GROUP_SIZE, ROW_GROUP_SIZE)
        ok = rg.equals(slice_i)
        assert ok, f"rg[{i}] 整组内容不匹配原表切片"
        print(f"  rg[{i}].equals(origin.slice({i*ROW_GROUP_SIZE}, {ROW_GROUP_SIZE})) = True  ✓")

    # ---- ④ 组间无缝：所有组拼接 == 一次性全量读 ----
    print("\n[④] concat(所有 rg) vs pq.read_table(整体)：")
    parts = [pf.read_row_group(i) for i in range(pf.num_row_groups)]
    concat_table = pa.concat_tables(parts)
    whole_table = pq.read_table(in_path, decryption_properties=dec_props)
    assert concat_table.num_rows == whole_table.num_rows == origin.num_rows
    assert concat_table.equals(whole_table), "分组拼接与整体读结果不一致（组间有重复/遗漏/错位）"
    assert concat_table.equals(origin), "分组拼接与原表不一致"
    print(f"  concat.num_rows={concat_table.num_rows}  whole.num_rows={whole_table.num_rows}  "
          f"origin.num_rows={origin.num_rows}  ✓")
    print(f"  concat.equals(whole)=True  concat.equals(origin)=True  ✓")

    print("\n========== 边界校验全部通过 ==========")


if __name__ == "__main__":
    table = build_random_table()
    write_encrypted(table, OUT_PATH)
    iter_read_by_rowgroup(OUT_PATH)
    verify_rowgroup_boundary(OUT_PATH, table)
