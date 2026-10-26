# DuckDB Parquet Modular Encryption (PME) 使用说明

本工程在 DuckDB 原生 Parquet encryption（简易 footer-key 模式）基础上，补齐了与
[Parquet Modular Encryption (PME) 规范](https://github.com/apache/parquet-format/blob/master/Encryption.md)
对齐的能力，可读写 PyArrow / Spark / Impala 等生态产出的 PME 加密文件。

本文档说明功能范围、SQL 使用方式、JDBC/CLI 的差异点、以及常见错误排查。

---

## 1. 功能速览

| 能力 | PR | SQL 字段 | 本工程状态 |
|---|---|---|---|
| Footer-key 全文件加密 | PR-1 | `footer_key` / `footer_key_value` | ✅ 读 + 写（PME-兼容） |
| 列级密钥（Column keys） | PR-2 | `column_keys` / `column_key_values` | ✅ 读 + 写 |
| aad_prefix（inline 存储） | PR-3 | `aad_prefix` | ✅ 读 + 写 |
| aad_prefix（外部注入） | PR-3 | `supply_aad_prefix` | ✅ 读 + 写 |
| KMS / Envelope encryption | PR-4 | `kms_client` / `footer_master_key_id` / `column_master_key_ids` / `double_wrapping` | ✅ 内置 **本地 KMS**（`PRAGMA register_local_kms`，PyArrow PKMT1 兼容）；外部 KMS 需用户自行 `Register(...)` |
| plaintext_footer | PR-3 | `plaintext_footer` | ❌ 显式抛未实现错误 |
| AES_GCM_CTR_V1 | - | - | ❌ 显式抛未实现错误 |

> 读写路径默认走 **AES_GCM_V1**，与 PyArrow / Spark / Impala 产出的 PME 文件完全互通。

---

## 2. 密钥注册：`PRAGMA add_parquet_key`

所有通过 `footer_key` / `column_keys` 等按**名**引用的密钥，必须先注册到 session 级密钥缓存。

```sql
-- 注册一个 16 / 24 / 32 字节的 AES 密钥（文本或十六进制字符串都按原字节使用）
PRAGMA add_parquet_key('<key_name>', '<raw_key_bytes>');
```

说明：
- 第二个参数是**原始字节**，不是 base64 / hex 解码后的值。
  例如 `'01234567891123450123456789112345'` 实际作为 32 字节 ASCII 用作 AES-256-GCM 的 key。
- 密钥只保存在当前连接的 session（`ObjectCache`），**不持久化、不跨连接共享**。
- 测试里会用 `require noforcestorage` 关闭 force-storage，避免 reload 后密钥丢失导致误报。

如果你不想注册密钥而直接传入字节，用 `footer_key_value` / `column_key_values`（见下文）。

---

## 3. SQL 使用示例

所有示例均从仓库里的测试文件抽取，可直接复用。

### 3.1 Footer-key：整个文件用同一把密钥

```sql
PRAGMA add_parquet_key('fk256', '01234567891123450123456789112345');

-- 写入
COPY (SELECT 42 AS i)
TO 'enc.parquet'
(ENCRYPTION_CONFIG {footer_key: 'fk256'});

-- 读取
SELECT * FROM read_parquet(
  'enc.parquet',
  encryption_config={footer_key: 'fk256'}
);
```

多 batch / 多 page 的大数据集同样生效（下例写入 10w 行、每行 128 字节字符串，用于触发多 DATA_PAGE）：

```sql
COPY (SELECT range AS i, repeat('x', 128) AS s FROM range(100000))
TO 'big_enc.parquet'
(ENCRYPTION_CONFIG {footer_key: 'fk256'});

SELECT count(*) FROM read_parquet('big_enc.parquet',
                                   encryption_config={footer_key: 'fk256'});
```

### 3.2 Column keys：每列不同密钥

`column_keys` 的 key 是**列的 path_in_schema**，顶层列直接用列名；嵌套列用 `parent.child` 的点分形式。
未在 `column_keys` 中列出的列，自动用 `footer_key` 加密。

```sql
PRAGMA add_parquet_key('fk', '01234567891123450123456789112345');
PRAGMA add_parquet_key('ka', '0123456789abcdef0123456789abcdef');
PRAGMA add_parquet_key('kb', 'fedcba9876543210fedcba9876543210');

-- 列 a → ka，列 b → kb，列 c → fk（默认 footer key）
COPY (SELECT range AS a, range * 2 AS b, repeat('z', 32) AS c FROM range(10000))
TO 'colkeys.parquet'
(ENCRYPTION_CONFIG {
  footer_key: 'fk',
  column_keys: {a: 'ka', b: 'kb'}
});

-- 读取时需提供完整列映射
SELECT min(a), max(b), count(DISTINCT c)
FROM read_parquet('colkeys.parquet',
                  encryption_config={footer_key: 'fk',
                                     column_keys: {a: 'ka', b: 'kb'}});
```

**失败场景**：

| 错误操作 | 报错类型 |
|---|---|
| 读时漏传某列的 key | `Invalid Input Error`（反序列化失败 / GCM tag 校验失败） |
| 读时某列 key 错配 | `Invalid Input Error`（GCM tag 校验失败） |

### 3.3 直接传密钥字节（不走 PRAGMA）

`column_keys` / `footer_key` 对应**key_name**；若你希望跳过 PRAGMA，直接传密钥字节，用这两个 "value" 版本：

```sql
COPY (SELECT 1 AS a, 2 AS b) TO 'raw.parquet' (ENCRYPTION_CONFIG {
  footer_key_value: '01234567891123450123456789112345'::BLOB,
  column_key_values: {
    a: '0123456789abcdef0123456789abcdef'::BLOB
  }
});
```

> ⚠️ `footer_key_value` / `column_key_values` 期待的是 `BLOB`，底层直接按**原字节**作为 AES key。

### 3.4 AAD prefix（PME aad_prefix）

PME 规范允许在 AAD 中拼入一段用户自定义的 `aad_prefix`，用于防止跨文件/跨场景的密文重放攻击。

两种模式：

#### 模式 A：Inline（prefix 存入文件）

写入时把 `aad_prefix` 塞进 `FileCryptoMetaData`，读取时**自动识别**，无需额外传参。

```sql
COPY (SELECT 42 AS i) TO 'prefix_inline.parquet'
(ENCRYPTION_CONFIG {footer_key: 'fk', aad_prefix: 'myapp_v1'});

-- 读：无需显式传 aad_prefix
SELECT * FROM read_parquet('prefix_inline.parquet',
                            encryption_config={footer_key: 'fk'});

-- 读：显式提供同样的 aad_prefix 也 OK
SELECT * FROM read_parquet('prefix_inline.parquet',
                            encryption_config={footer_key: 'fk', aad_prefix: 'myapp_v1'});

-- 读：显式提供不匹配的 aad_prefix → Invalid Input Error
```

#### 模式 B：Supply（prefix 外部注入，不写入文件）

写入时设置 `supply_aad_prefix: true`，文件内**不**保存 prefix；读取时**必须**提供正确的 prefix。

```sql
-- 写入
COPY (SELECT 7 AS i) TO 'prefix_supply.parquet'
(ENCRYPTION_CONFIG {
  footer_key: 'fk',
  aad_prefix: 'secret_prefix',
  supply_aad_prefix: true
});

-- 不传 prefix → Invalid Input Error
SELECT * FROM read_parquet('prefix_supply.parquet',
                            encryption_config={footer_key: 'fk'});

-- 传正确 prefix → OK
SELECT * FROM read_parquet('prefix_supply.parquet',
                            encryption_config={footer_key: 'fk',
                                              aad_prefix: 'secret_prefix'});
```

### 3.5 encryption_config 参数速查

| 参数名 | 类型 | 含义 |
|---|---|---|
| `footer_key` | `VARCHAR` | footer 密钥的 **key name**（需 `add_parquet_key` 预注册） |
| `footer_key_value` | `BLOB` | footer 密钥的**原始字节**（与 `footer_key` 二选一） |
| `column_keys` | `STRUCT { col_path => key_name }` 或 `MAP(VARCHAR, VARCHAR)` | 列级密钥名映射 |
| `column_key_values` | `STRUCT { col_path => BLOB }` | 列级密钥原始字节映射 |
| `aad_prefix` | `VARCHAR` | PME AAD 前缀（写入 → inline；读取 → 校验） |
| `supply_aad_prefix` | `BOOLEAN` | 写入时 `true` 则不把 prefix 存进文件；读取时参数无效 |
| `plaintext_footer` | `BOOLEAN` | ❌ 当前抛未实现错误 |
| `kms_client` | `VARCHAR` | 用于 envelope encryption 的 KMS 实例名（见 §4） |
| `footer_master_key_id` | `VARCHAR` | footer 的 master key 标识（KMS 可识别） |
| `column_master_key_ids` | `STRUCT { col_path => mk_id }` | 列级 master key 标识 |
| `double_wrapping` | `BOOLEAN` | 是否启用双层包装（KEK 层） |

未知字段会抛 `Unknown key in encryption_config`。

---

## 4. KMS / Envelope encryption（PR-4）

> 本工程内置了一个 **PyArrow-compatible 本地 KMS**（AES-GCM-256 包装 DEK，`key_metadata` 使用
> PyArrow 17 的 `keyMaterialType=PKMT1` JSON 格式），通过 `PRAGMA register_local_kms('<name>')`
> 一行启用，**无需 C++ 代码、无需 JNI 改造**。如果你需要对接企业 KMS（AWS KMS / Vault / 内部 KMS），
> 仍可按 §4.5 的 C++ 接口自行扩展并注册。

### 4.1 概念

- **DEK**（Data Encryption Key）：由 Writer 随机生成，直接用于加密 Parquet 的 footer / columns。
- **MEK / MK**（Master Encryption Key）：由 KMS 托管，用于 **包装（wrap）** DEK。
- **key_metadata**：被 wrap 后的 DEK 的不透明字节串，存放在 Parquet 的
  `EncryptionWithColumnKey.key_metadata` 或 `EncryptionWithFooterKey.key_metadata`。
- **Envelope encryption** 的好处：Parquet 文件里永远不出现明文 DEK；只要 KMS 能响应 Unwrap，就能解密。

### 4.2 快速模式：内置 `LocalKmsClient` + `PRAGMA register_local_kms`（推荐）

**适用场景**：master keys 存在进程内存里（即"本地 KMS"），不需要调用外部 KMS 服务。

核心思路：
1. 用 `PRAGMA add_parquet_key(<master_key_id>, <raw_key_bytes>)` 把 master keys 注册到当前 session（**复用现有 PRAGMA**，无新概念）。
2. 用 `PRAGMA register_local_kms('<kms_name>')` 一键创建一个 `LocalKmsClient` 实例，**快照**当前 session 已注册的全部 parquet keys 作为它的 master-key 池，并注册到全局 `ParquetKmsRegistry`。
3. 之后在 `encryption_config.kms_client` 里引用该 `<kms_name>` 即可。

```sql
-- 1) 注册 master keys（AES-GCM-256 要求 16/24/32 字节）
PRAGMA add_parquet_key('mk_footer', '01234567891123450123456789112345');
PRAGMA add_parquet_key('mk_col_a',  '0123456789abcdef0123456789abcdef');

-- 2) 创建一个名为 'local' 的本地 KMS 实例（捕获当前 session 的 keys 作为 master keys）
PRAGMA register_local_kms('local');

-- 3) 写入：footer 走 mk_footer，列 a 走 mk_col_a，其他列继承 footer DEK
COPY (SELECT range AS a, range * 2 AS b FROM range(10000))
TO 'kms.parquet' (ENCRYPTION_CONFIG {
    kms_client: 'local',
    footer_master_key_id: 'mk_footer',
    column_master_key_ids: {a: 'mk_col_a'}
});

-- 4) 读取：传同样的 kms_client + master key ids 即可
SELECT count(*) FROM read_parquet('kms.parquet',
    encryption_config={
        kms_client: 'local',
        footer_master_key_id: 'mk_footer',
        column_master_key_ids: {a: 'mk_col_a'}
    });
```

**on-wire 格式**（存入 Parquet 的 `key_metadata` 字段）：

```json
{"keyMaterialType":"PKMT1",
 "internalStorage":true,
 "doubleWrapping":false,
 "kmsInstanceID":"local",
 "kmsInstanceURL":"",
 "masterKeyID":"mk_footer",
 "wrappedDEK":"<base64(AES-GCM-256(ct||tag))>",
 "iv":"<base64(12-byte-iv)>"}
```

> 该格式与 PyArrow 17 的 `KmsClient.wrap_key(...)` 内部产物完全一致 ——
> 这意味着 **DuckDB(本工程) ↔ PyArrow 17 KMS 文件可以双向 round-trip**，只要双方用同一组 master keys。

**注意事项**：
- `register_local_kms` **只拍一次快照**：之后再 `add_parquet_key` 新注册的密钥**不会**自动进入该 KMS 实例的 master-key 池，需要重新 `register_local_kms('local')` 覆盖同名实例。
- `ParquetKmsRegistry` 是**进程级全局单例**，而 `ParquetKeys` 是**连接级**（ObjectCache）。因此 `register_local_kms` 做的事情本质上是"把当前连接的 keys 快照升级为全局 KMS"。
- master key 必须是 16/24/32 字节；否则在 wrap/unwrap 时抛 `Invalid Input Error`。

### 4.3 SQL 使用示例（通用）

```sql
-- footer_key 可省略；此时 DEK 由 writer 随机生成并由 KMS 包装
COPY (SELECT * FROM t) TO 'kms.parquet' (ENCRYPTION_CONFIG {
  kms_client: 'local',
  footer_master_key_id: 'master_key_1',
  column_master_key_ids: {sensitive_col: 'master_key_sensitive'},
  double_wrapping: false
});

SELECT * FROM read_parquet('kms.parquet',
                            encryption_config={
                              kms_client: 'local',
                              footer_master_key_id: 'master_key_1',
                              column_master_key_ids: {sensitive_col: 'master_key_sensitive'}
                            });
```

### 4.4 PyArrow 互通示例

```python
# PyArrow 17 side: 用相同的 master_key_id -> bytes 映射
import pyarrow.parquet.encryption as pe

class MyLocalKmsClient(pe.KmsClient):
    def __init__(self, master_keys):
        super().__init__()
        self.master_keys = master_keys
    def wrap_key(self, key_bytes, master_key_id):
        # PyArrow 内置的 PKMT1 wrap；只要双方对同一 master_key_id 持相同 bytes 即可互通
        ...
    def unwrap_key(self, wrapped_key, master_key_id):
        ...

# PyArrow 读 DuckDB 产出的 kms.parquet 文件，或反之，都能解密
```

实际跑通的样例可见 `examples/pme-pyarrow-interop/`。

### 4.5 外部 KMS：C++ 自定义 KmsClient

如需对接 AWS KMS / Vault / 公司内部 KMS，仍走原 C++ 扩展接口：

```cpp
#include "parquet_crypto.hpp"

class MyKmsClient : public duckdb::ParquetKmsClient {
public:
    std::string WrapKey(const std::string &dek, const std::string &master_key_id) override {
        // 调用你的 KMS，用 master_key_id 对应的 MK 加密 dek，返回不透明 blob
        return my_kms_wrap(dek, master_key_id);
    }
    std::string UnwrapKey(const std::string &key_metadata, const std::string &master_key_id) override {
        return my_kms_unwrap(key_metadata, master_key_id);
    }
};

// 进程启动时注册（例如在 extension load 或 main() 里）
duckdb::ParquetKmsRegistry::Get().Register(
    "my_kms",
    std::make_shared<MyKmsClient>()
);
```

> 自定义 KmsClient 的 `key_metadata` 格式**不要求**与 PyArrow 兼容；只要你的 Wrap/Unwrap 自洽即可。
> 如果希望产出的文件也能被 PyArrow 17 读取，请 emit 相同的 PKMT1 JSON 格式（见 §4.2 的
> on-wire 示例）。

---

## 5. 调用方式

### 5.1 duckdb CLI

```bash
./duckdb << 'SQL'
PRAGMA add_parquet_key('fk256', '01234567891123450123456789112345');
COPY (SELECT 42 AS i) TO '/tmp/enc.parquet'
  (ENCRYPTION_CONFIG {footer_key: 'fk256'});
SELECT * FROM read_parquet('/tmp/enc.parquet',
                            encryption_config={footer_key: 'fk256'});
SQL
```

### 5.2 JDBC（Java）

> JDBC 使用的 `libduckdb_java.so` 来自独立仓库 `duckdb-java`，vendor 了一份 DuckDB 源码。
> 要让 JDBC 也带上本工程的 PME 补丁，需用本工程源码替换其 `src/duckdb/`，再构建。
> 详见 `scripts/pme-linux-build/README.md`。

```java
try (var conn = DriverManager.getConnection("jdbc:duckdb:");
     var st = conn.createStatement()) {
    st.execute("PRAGMA add_parquet_key('fk256', '01234567891123450123456789112345')");
    st.execute("COPY (SELECT 42 AS i) TO '/tmp/enc.parquet'" +
               " (ENCRYPTION_CONFIG {footer_key: 'fk256'})");
    try (var rs = st.executeQuery(
            "SELECT * FROM read_parquet('/tmp/enc.parquet'," +
            " encryption_config={footer_key: 'fk256'})")) {
        while (rs.next()) System.out.println(rs.getInt(1));
    }
}
```

### 5.3 PyArrow 互通

本工程产出的 PME 文件可被 PyArrow 直接解密读取（使用 `pyarrow.parquet.read_table` 并通过
`decryption_properties`/`CryptoFactory` 传入对应密钥 / KMS）。反过来，PyArrow 产出的 PME 文件也
可被 DuckDB 读取（配置相同的 `footer_key` / `column_keys` / `aad_prefix`）。

---

## 6. 版本/生态互通

| 场景 | 能否 round-trip |
|---|---|
| DuckDB(本工程) ↔ DuckDB(本工程) | ✅ |
| DuckDB(本工程) → PyArrow 读 | ✅（PME AES_GCM_V1） |
| PyArrow 写 → DuckDB(本工程) 读 | ✅ |
| DuckDB(本工程) KMS ↔ PyArrow 17 KMS | ✅ 本地 KMS 走 PKMT1 JSON（见 §4.2），双方共享同一组 master keys 即可 |
| DuckDB(官方 release) 读本工程产物 | ⚠️ 简单 footer_key 可读；column_keys/aad_prefix 不保证 |
| 读 `AES_GCM_CTR_V1` 加密的文件 | ❌ 抛未实现错误 |
| plaintext_footer 模式 | ❌ 抛未实现错误 |

---

## 7. 错误排查

| 现象 | 可能原因 | 排查建议 |
|---|---|---|
| `No key with name "X" exists` | 没先 `PRAGMA add_parquet_key` | 注册密钥，或改用 `*_key_value` 直传字节 |
| `Unknown key in encryption_config "X"` | SQL 字段拼写错误 | 对照 §3.5 速查表 |
| 读取时报 `Invalid Input Error`（GCM tag） | key / aad_prefix / column_keys 任一不匹配 | 确认写入时的 config 与读取完全一致 |
| `encryption_config.kms_client='X' is not registered` | KMS Client 未注册 | 本地 KMS 用 `PRAGMA register_local_kms('X')`；外部 KMS 按 §4.5 在进程启动时 `Register(...)` |
| `register_local_kms: no parquet keys registered in this session` | 调 `register_local_kms` 前未注册任何 master key | 先 `PRAGMA add_parquet_key('<mk_id>','<key_bytes>')` |
| `LocalKmsClient: master key id 'X' not configured` | 用了未注册的 `master_key_id` | `PRAGMA add_parquet_key(...)` 补齐后 **重新** `register_local_kms(...)`（快照是一次性的） |
| `LocalKmsClient: master key 'X' has invalid length` | master key 字节数非 16/24/32 | 换成合法的 AES-128/192/256 bytes |
| `LocalKmsClient: unsupported keyMaterialType ...` | 文件 `key_metadata` 不是 PKMT1 JSON（例如旧版 LocalWrap 或外部 KMS） | 用匹配该格式的 KmsClient 读取 |
| `AES_GCM_CTR_V1 ... not supported` | 文件用非 PME-GCM 加密 | 升级生产侧写入到 AES_GCM_V1 |
| `plaintext_footer ... not implemented` | 用了 `plaintext_footer: true` | 当前不支持，去掉该参数 |
| JDBC 下 PME 行为与 CLI 不一致 | `libduckdb_java.so` 没替换 vendored duckdb | 参照 `scripts/pme-linux-build/README.md` 重新构建 JDBC |

---

## 8. 自测与回归

本工程附带 4 份测试，位于 `test/sql/copy/parquet/`：

| 测试文件 | 覆盖 |
|---|---|
| `parquet_encryption.test` | 原生 footer_key 基础用例（兼容旧行为） |
| `encryption/pme_roundtrip_footer_key.test` | PR-1：单行 + 10w 行 + 多 batch |
| `encryption/pme_column_keys.test` | PR-2：列级密钥、漏传 / 错配报错 |
| `encryption/pme_aad_prefix.test` | PR-3：inline + supply + 错配报错 |

### 本机跑

```bash
make debug -j
UNIT=build/debug/test/unittest
"$UNIT" "test/sql/copy/parquet/parquet_encryption.test"
"$UNIT" "test/sql/copy/parquet/encryption/pme_roundtrip_footer_key.test"
"$UNIT" "test/sql/copy/parquet/encryption/pme_column_keys.test"
"$UNIT" "test/sql/copy/parquet/encryption/pme_aad_prefix.test"
```

### Linux 远端验证

参考 `scripts/pme-linux-build/README.md`，提供：
- `pack-source.sh`：打成 tar.gz 传输
- `build-linux-remote.sh`：rsync + 远端自动构建跑测试
- `setup-linux-remote.sh`：一次性安装远端构建依赖

---

## 9. 相关源码定位

| 功能 | 文件 |
|---|---|
| `ParquetEncryptionConfig` 参数解析 | `extension/parquet/parquet_crypto.cpp`（`ParquetEncryptionConfig(ClientContext&, const Value&)`） |
| `CryptoMetaData` / AAD 构造 | `extension/parquet/parquet_crypto.cpp`（`InitializeWithPrefix`, `WritePrefix`） |
| 写路径 PME 接入 | `extension/parquet/parquet_writer.cpp`（FileCryptoMetaData、per-column crypto_metadata） |
| 列级加密分发 | `extension/parquet/writer/primitive_column_writer.cpp`（`FinalizeWrite`） |
| 读路径 PME 接入 | `extension/parquet/parquet_reader.cpp`（footer 解密、`encrypted_column_metadata`） |
| 列级 AAD / 跨 batch page 计数 | `extension/parquet/column_reader.cpp`（`InitializeCryptoMetadata`, `ReadPageHeaders`） |
| KMS 抽象 | `extension/parquet/include/parquet_crypto.hpp`（`ParquetKmsClient`、`ParquetKmsRegistry`） |
| 本地 KMS 实现 | `extension/parquet/parquet_crypto.cpp`（`LocalKmsClient`：AES-GCM-256 + PKMT1 JSON） |
| `PRAGMA register_local_kms` | `extension/parquet/parquet_crypto.cpp`（`ParquetCrypto::RegisterLocalKms`），注册入口在 `extension/parquet/parquet_extension.cpp` |

