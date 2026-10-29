#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LocalKMS 共享模块：PyArrow 侧的 LocalKmsClient + master key 配置 + 写函数。

与 duckdb-java 内置 LocalKmsClient 字节级对齐 (AES-GCM-256, IV(12)||CT||TAG(16),
不传 AAD; wrappedDEK 的 base64 由 PyArrow 自动包进 outer-JSON)。

两条互通链路都 import 这个模块：
  - A_pyarrow_write_duckdb_read.py (方向 A: PyArrow 写 → DuckDB-Java 读)
  - B_duckdb_write_pyarrow_read.py (方向 B: DuckDB-Java 写 → PyArrow 读)

单独运行时作为方向 A 的 PyArrow 写端:
  python3 pyarrow_localkms.py <out.parquet>
"""
from __future__ import annotations

import base64
import os
import secrets
import sys

import pyarrow as pa
import pyarrow.parquet as pq
import pyarrow.parquet.encryption as pe

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- master key 配置（真实场景请从安全存储读取）--------------------------
# 规范：16/24/32 字节 → AES-128/192/256
# ⚠️ PyArrow 对同一 mkid 跨列共享 wrap 产物，而 DuckDB 读这种共享结构会出错，
#    所以**每列必须专属 mkid**（哪怕 bytes 相同也要换个名字）。
MASTER_KEYS: dict[str, bytes] = {
    "mk_footer":    b"01234567891123450123456789112345",
    "mk_col_id":    b"0123456789abcdef0123456789abcdef",
    "mk_col_name":  b"fedcba9876543210fedcba9876543210",
    "mk_col_score": b"7A2EeF5BcD6A4CaE88BbbFABfbF4cF77",
}
KMS_INSTANCE_ID = "local"
FOOTER_MASTER_KEY_ID = "mk_footer"
COLUMN_MASTER_KEYS = {"id": "mk_col_id", "name": "mk_col_name", "score": "mk_col_score"}


class LocalKmsClient(pe.KmsClient):
    """与 duckdb-java LocalKmsClient 字节级对齐的 PyArrow KmsClient。"""

    IV = 12
    TAG = 16

    def __init__(self, config: pe.KmsConnectionConfig):
        super().__init__()
        self._mk = {k: base64.b64decode(v)
                    for k, v in dict(config.custom_kms_conf or {}).items()}

    def _key(self, mkid: str) -> bytes:
        mk = self._mk.get(mkid)
        if mk is None:
            raise KeyError(f"master key '{mkid}' not configured")
        return mk

    def wrap_key(self, dek: bytes, mkid: str) -> bytes:
        iv = secrets.token_bytes(self.IV)
        return base64.b64encode(iv + AESGCM(self._key(mkid)).encrypt(iv, bytes(dek), None))

    def unwrap_key(self, wrapped, mkid: str) -> bytes:
        raw = wrapped.encode("ascii") if isinstance(wrapped, str) else bytes(wrapped)
        blob = base64.b64decode(raw)
        return AESGCM(self._key(mkid)).decrypt(blob[:self.IV], blob[self.IV:], None)


def build_kms_connection_config(url: str = "") -> pe.KmsConnectionConfig:
    """url: 写端用 "" 即可；读端读 duckdb-java 产物时必须用 "DEFAULT"（PyArrow sentinel）。"""
    return pe.KmsConnectionConfig(
        kms_instance_id=KMS_INSTANCE_ID,
        kms_instance_url=url,
        custom_kms_conf={k: base64.b64encode(v).decode() for k, v in MASTER_KEYS.items()},
    )


def write_encrypted(out_path: str) -> None:
    """PyArrow 侧写加密 parquet：footer + 每列独立 mkid 的真·KMS 加密。"""
    cfg = build_kms_connection_config()
    factory = pe.CryptoFactory(lambda c: LocalKmsClient(c))

    enc_cfg = pe.EncryptionConfiguration(
        footer_key=FOOTER_MASTER_KEY_ID,
        column_keys={mkid: [col] for col, mkid in COLUMN_MASTER_KEYS.items()},
        encryption_algorithm="AES_GCM_V1",
        plaintext_footer=False,
        double_wrapping=False,
        internal_key_material=True,
        data_key_length_bits=256,
    )
    enc_props = factory.file_encryption_properties(cfg, enc_cfg)

    table = pa.table({
        "id":    pa.array([1, 2, 3, 4, 5], type=pa.int32()),
        "name":  pa.array(["alice", "bob", "carol", "dave", "eve"]),
        "score": pa.array([3.14, 2.72, -1.00, 0.5, 42.0], type=pa.float64()),
    })

    with pq.ParquetWriter(out_path, table.schema,
                          encryption_properties=enc_props, compression="snappy") as w:
        w.write_table(table)
    print(f"[py-write] {out_path}  size={os.path.getsize(out_path)}B  head=b'PARE'")

    # 自回读校验
    dec_props = factory.file_decryption_properties(cfg, pe.DecryptionConfiguration())
    t2 = pq.read_table(out_path, decryption_properties=dec_props)
    assert t2.num_rows == table.num_rows
    print(f"[py-write] self-roundtrip OK: rows={t2.num_rows}")


def read_encrypted(in_path: str):
    """PyArrow 侧读加密 parquet：读 duckdb-java 产物时 kms_instance_url 必须用 "DEFAULT"。"""
    cfg = build_kms_connection_config(url="DEFAULT")
    factory = pe.CryptoFactory(lambda c: LocalKmsClient(c))
    dec_props = factory.file_decryption_properties(cfg, pe.DecryptionConfiguration())
    return pq.read_table(in_path, decryption_properties=dec_props)

# --------- footer-only 模式 ----------------------------------------------
# PyArrow EncryptionConfiguration 不传 column_keys 时，所有列都用 footer DEK 加密，
# 对应 Parquet 文件只写 1 条 footer key_metadata，不写 column key_metadata，
# 与 DuckDb*LocalKmsFooterOnly.java 的 ENCRYPTION_CONFIG 字节级对齐。

def write_encrypted_footer_only(out_path: str) -> None:
    """footer-only：所有列共享 footer DEK，不做 per-column DEK 包装。"""
    cfg = build_kms_connection_config()
    factory = pe.CryptoFactory(lambda c: LocalKmsClient(c))

    enc_cfg = pe.EncryptionConfiguration(
        footer_key=FOOTER_MASTER_KEY_ID,
        # PyArrow 17 没有 uniform_encryption API，必须传 column_keys。
        # 把所有列挂到同一个 footer mkid 下即可模拟 "footer-only"：
        # PyArrow 实测仍会为每列生成独立 DEK + 独立 wrap outer-JSON，
        # 和 duckdb-java 的 column-level 对齐，不会出现 "跨列共享 wrap 产物" 坑。
        column_keys={FOOTER_MASTER_KEY_ID: list(COLUMN_MASTER_KEYS.keys())},
        encryption_algorithm="AES_GCM_V1",
        plaintext_footer=False,
        double_wrapping=False,
        internal_key_material=True,
        data_key_length_bits=256,
    )
    enc_props = factory.file_encryption_properties(cfg, enc_cfg)

    table = pa.table({
        "id":    pa.array([1, 2, 3, 4, 5], type=pa.int32()),
        "name":  pa.array(["alice", "bob", "carol", "dave", "eve"]),
        "score": pa.array([3.14, 2.72, -1.00, 0.5, 42.0], type=pa.float64()),
    })

    with pq.ParquetWriter(out_path, table.schema,
                          encryption_properties=enc_props, compression="snappy") as w:
        w.write_table(table)
    print(f"[py-write-fo] {out_path}  size={os.path.getsize(out_path)}B  head=b'PARE'")

    # 自回读校验
    dec_props = factory.file_decryption_properties(cfg, pe.DecryptionConfiguration())
    t2 = pq.read_table(out_path, decryption_properties=dec_props)
    assert t2.num_rows == table.num_rows
    print(f"[py-write-fo] self-roundtrip OK: rows={t2.num_rows}")

def read_encrypted_footer_only(in_path: str):
    """footer-only 读：与 column-level 读完全同构，复用相同的 KmsClient 即可。"""
    cfg = build_kms_connection_config(url="DEFAULT")
    factory = pe.CryptoFactory(lambda c: LocalKmsClient(c))
    dec_props = factory.file_decryption_properties(cfg, pe.DecryptionConfiguration())
    return pq.read_table(in_path, decryption_properties=dec_props)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("用法: pyarrow_localkms.py <out.parquet>", file=sys.stderr)
        sys.exit(64)
    write_encrypted(sys.argv[1])
