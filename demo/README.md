# DuckDB-Java ↔ PyArrow Parquet Modular Encryption 互通样例

本目录展示 **DuckDB-Java（PME 版 duckdb_jdbc jar）** 与 **PyArrow Python API** 之间基于 LocalKMS 真·KMS 模式的 Parquet 加密**双向互通**，含 **footer + 每列独立 DEK** 的 column-level 加密。两侧只共享 master key，DEK 永不出进程，与 Apache Arrow / PyArrow wire-level 兼容。

参考：[PME-USAGE.md](file:///Users/luguoji/work/dev/other/duckdb-java/docs/PME-USAGE.md) §4

## 📁 目录结构

```
pme-pyarrow-interop/
├── README.md
├── pyarrow_localkms.py                  共享模块：LocalKmsClient + 配置 + 写/读函数
├── A_pyarrow_write_duckdb_read.py       方向 A 一键入口 ✅
├── B_duckdb_write_pyarrow_read.py       方向 B 一键入口 ✅
├── DuckDbReadLocalKms.java              Java 读端（方向 A 用，column-level KMS）
└── DuckDbWriteLocalKms.java             Java 写端（方向 B 用，column-level KMS）
```

## 🚀 快速开始

### 前置依赖

```bash
pip3 install "pyarrow>=17.0.0" cryptography
java -version    # 需要 JDK 11+
# 带 PME 补丁的 duckdb_jdbc jar 默认路径：<repo-root>/lib/duckdb_jdbc-1.5.4.0.jar
# 自定义: export DUCKDB_PME_JAR=/path/to/duckdb_jdbc.jar
```

### 跑双向互通

```bash
cd /Users/luguoji/work/dev/java/maas-server/scripts/pme-pyarrow-interop

# 方向 A: PyArrow 写 → DuckDB-Java 读
python3 A_pyarrow_write_duckdb_read.py

# 方向 B: DuckDB-Java 写 → PyArrow 读
python3 B_duckdb_write_pyarrow_read.py
```

两条链路预期尾部都是：
```
[OK] ... 加密互通成功 ✅
```

## 🧩 原理与关键点

### on-wire 格式（PyArrow 17 对齐，duckdb-java LocalKmsClient 严格遵循）

Footer `key_metadata`（存在 `FileCryptoMetaData.key_metadata`，明文可见）:
```json
{"keyMaterialType":"PKMT1",
 "isFooterKey":true,
 "kmsInstanceID":"local",
 "kmsInstanceURL":"",
 "internalStorage":true,
 "doubleWrapping":false,
 "masterKeyID":"mk_footer",
 "wrappedDEK":"<base64( IV(12) || CT || TAG(16) )>"}
```

Column `key_metadata`（存在 `EncryptionWithColumnKey.key_metadata`，嵌在加密的 FileMetaData 里）:
```json
{"keyMaterialType":"PKMT1",
 "isFooterKey":false,
 "internalStorage":true,
 "doubleWrapping":false,
 "masterKeyID":"mk_col_xxx",
 "wrappedDEK":"<base64( IV(12) || CT || TAG(16) )>"}
```

> ⚠️ **spec 和实现的差异**：Apache Arrow 的 `key_material.h` **spec** 说 `internalStorage`/`doubleWrapping` 是 **footer-only** 字段，但 **PyArrow 17 C++ reader 的实际实现**强制要求这两个字段在**每个** KeyMaterial 中都存在（footer + column），否则抛 `ArrowKeyError: Key 'internalStorage' does not exist`。为保证互通，duckdb-java 的 column key_metadata 也无条件 emit 这两个字段。

### 双方对齐的 4 条规则

1. 算法：**AES-GCM-256**，master key 必须 16/24/32 字节；
2. IV：**12 字节随机**，直接前置到 wrappedDEK（不是独立 JSON 字段）；
3. wrap/unwrap 过程**不传 AAD**（对齐 LocalKmsClient::WrapKey 的 `aes->Finalize(nullptr, 0, tag, TAG_BYTES)`）；
4. PyArrow 的 `wrap_key` 返回值被 PyArrow 自动包进 outer-JSON 的 `wrappedDEK` 字段；本样例 wrap_key 直接返回 `base64(IV||CT||TAG)`，字节级对齐 duckdb-java 侧的 UnwrapKey。

## ⚠️ 两个关键坑（已踩，必读）

### 1. 方向 A：PyArrow 每列必须配独立 mkid

PyArrow 对同一 mkid 只调一次 `wrap_key` 并把产物共享给所有共 mkid 的列，导致 Parquet 文件里多列共用同一个 key_metadata；而 DuckDB-PME 读路径对这种共享层级解析有 bug，表现为 IO error `attempted to read N bytes from location M`。

**解法**：给每列都配独立 mkid（哪怕 mk bytes 相同也要起不同名字）。本样例的 `pyarrow_localkms.py` 用 `mk_col_id` / `mk_col_name` / `mk_col_score` 三个独立 mkid 绕开此问题。

### 2. 方向 B：PyArrow 读必须用 `kms_instance_url="DEFAULT"`

PyArrow 17 reader 对 KMS 加密文件要求 `KmsConnectionConfig.kms_instance_url` 必须是 `"DEFAULT"`（PyArrow 内部 sentinel）；若传空字符串或不传会报：
```
KMS instance ID is missing both in both kms connection configuration and file key material
```

这不是文件格式问题 —— 是 PyArrow 17 reader 的严格安全行为（源自 CVE-2026-73334 修复后对 URL 字段的保护）。无论文件里的 `kmsInstanceURL` 是什么值，PyArrow 读端**都必须显式传 `"DEFAULT"`**才能通过校验。

**解法**：`pyarrow_localkms.py` 的 `read_encrypted()` 已经把 url 硬编码为 `"DEFAULT"`，直接用即可。

## 🗒️ FAQ

**Q: 为什么必须 `SET force_mbedtls_unsafe = 'true'`？**  
A: JDBC 启动时 DuckDB 的加密模块会尝试加载 httpfs 以获得 OpenSSL AES；但 OpenSSL AES 的 PME AAD 分支在当前版本会触发 `InternalException`。强制 mbedtls 后 PME 走的是 DuckDB 内置的 mbedtls AES 实现，正常工作。该 setting 是 DuckDB 核心内建，不依赖任何扩展。

**Q: 本样例和 raw-key 模式（不走 KMS）相比有啥优势？**  
A: raw-key 模式 DuckDB 产物没有 `key_metadata`，PyArrow 17 Python binding 没有 "explicit footer key" 入口，所以 **PyArrow 根本读不了 raw-key 产物**；而 LocalKMS 模式产物带标准 PKMT1 outer-JSON，PyArrow 可以直接解密。所以如果有互通需求，必须走 KMS 模式。

**Q: 文件实际写了几份 key_metadata？**  
A: 本样例文件（5 行小文件 ~1950B）写了 **4 份**：
- 1 份 footer `key_metadata`（在明文的 `FileCryptoMetaData` 里）
- 3 份 column `key_metadata`（分别在 id/name/score 列的 `EncryptionWithColumnKey` 里，这部分又被整体加密到 FileMetaData 中，所以 raw bytes 中搜不到明文 JSON）

每份 key_metadata 都是独立随机的 32 字节 DEK 用对应 master key AES-GCM-256 包装后的产物。
