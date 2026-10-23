//===----------------------------------------------------------------------===//
//                         DuckDB
//
// parquet_crypto.hpp
//
//
//===----------------------------------------------------------------------===//

#pragma once

#include "parquet_types.h"
#include "duckdb/common/allocator.hpp"
#include "duckdb/common/encryption_state.hpp"
#include "duckdb/common/encryption_functions.hpp"
#include "duckdb/storage/object_cache.hpp"

namespace duckdb {
class ParquetAdditionalAuthenticatedData;

using duckdb_apache::thrift::TBase;
using duckdb_apache::thrift::protocol::TProtocol;
using duckdb_parquet::ColumnChunk;
using duckdb_parquet::PageType;
class Allocator;
class BufferedFileWriter;

class ParquetKeys : public ObjectCacheEntry {
public:
	static ParquetKeys &Get(ClientContext &context);

public:
	void AddKey(const string &key_name, const string &key);
	bool HasKey(const string &key_name) const;
	const string &GetKey(const string &key_name) const;

public:
	static string ObjectType();
	string GetObjectType() override;
	optional_idx GetEstimatedCacheMemory() const override {
		return optional_idx {};
	}

private:
	unordered_map<string, string> keys;
};

//! Abstraction for a KMS (Key Management Service) client used by PME envelope encryption.
//! Users implement WrapKey (wrap a plaintext DEK with a master key, returning opaque `key_metadata`)
//! and UnwrapKey (reverse). PyArrow-compatible: `master_key_identifier` is the user-space name of the
//! master key stored in a KMS; `key_metadata` is the opaque blob stored in Parquet's
//! EncryptionWithColumnKey.key_metadata.
class ParquetKmsClient {
public:
	virtual ~ParquetKmsClient() = default;
	//! Wrap `dek` (data encryption key, raw bytes) with the master key identified by `master_key_id`.
	//! Returns the wrapped key metadata bytes which will be stored in the Parquet file.
	virtual string WrapKey(const string &dek, const string &master_key_id) = 0;
	//! Unwrap `key_metadata` (produced by WrapKey) using the master key identified by `master_key_id`.
	//! Returns the plaintext DEK bytes.
	virtual string UnwrapKey(const string &key_metadata, const string &master_key_id) = 0;
};

//! Global registry of KmsClient instances. Extensions register implementations by name; the
//! Parquet writer/reader resolves `encryption_config.kms_client` via this registry.
class ParquetKmsRegistry {
public:
	static ParquetKmsRegistry &Get();

	void Register(const string &name, shared_ptr<ParquetKmsClient> client);
	bool HasClient(const string &name) const;
	shared_ptr<ParquetKmsClient> GetClient(const string &name) const;

private:
	mutable std::mutex mu;
	unordered_map<string, shared_ptr<ParquetKmsClient>> clients;
};

struct CryptoMetaData {
	CryptoMetaData(Allocator &allocator);
	void Initialize(const std::string &unique_file_identifier_p, int16_t row_group_ordinal = -1,
	                int16_t column_ordinal = -1, int8_t module = -1, int16_t page_ordinal = -1);
	//! Initialize with both AAD prefix (optional, may be empty) and the file-unique AAD (8 bytes).
	//! Per PME spec the full AAD prefix is: aad_prefix || aad_file_unique.
	void InitializeWithPrefix(const std::string &aad_prefix_p, const std::string &unique_file_identifier_p,
	                          int16_t row_group_ordinal = -1, int16_t column_ordinal = -1, int8_t module = -1,
	                          int16_t page_ordinal = -1);
	void ClearAdditionalAuthenticatedData();
	void SetModule(int8_t module_p);
	bool IsEmpty() const;

public:
	//! Optional user-supplied AAD prefix (empty if not configured).
	string aad_prefix = "";
	//! The 8-byte random file identifier (AES_GCM_V1.aad_file_unique). Empty => legacy no-AAD mode.
	string unique_file_identifier = "";
	int8_t module;
	int16_t row_group_ordinal;
	int16_t column_ordinal;
	int16_t page_ordinal;

public:
	unique_ptr<ParquetAdditionalAuthenticatedData> additional_authenticated_data;
};

class ParquetAdditionalAuthenticatedData : public AdditionalAuthenticatedData {
public:
	explicit ParquetAdditionalAuthenticatedData(Allocator &allocator);
	~ParquetAdditionalAuthenticatedData() override;

public:
	idx_t GetPrefixSize() const;
	void Rewind() const;
	void WriteParquetAAD(const CryptoMetaData &crypto_meta_data);

private:
	//! Writes the AAD prefix part: aad_prefix (optional) || aad_file_unique.
	//! Per PME spec aad_prefix is only present when the config specifies it; aad_file_unique is 8 bytes.
	void WritePrefix(const std::string &aad_prefix, const std::string &aad_file_unique);
	void WriteSuffix(const CryptoMetaData &crypto_meta_data);

private:
	optional_idx additional_authenticated_data_prefix_size;
};

class ParquetEncryptionConfig {
public:
	explicit ParquetEncryptionConfig();
	ParquetEncryptionConfig(ClientContext &context, const Value &arg);
	ParquetEncryptionConfig(string footer_key);

public:
	static shared_ptr<ParquetEncryptionConfig> Create(ClientContext &context, const Value &arg);
	const string &GetFooterKey() const;

	//! Returns true if the given column path (dot-joined path_in_schema) has a dedicated column key.
	bool HasColumnKey(const string &path_in_schema_dot) const;
	//! Returns the per-column AES key bytes. Must only be called when HasColumnKey returns true.
	const string &GetColumnKey(const string &path_in_schema_dot) const;
	//! Returns the optional, user-supplied key_metadata associated with a column key (empty if none).
	const string &GetColumnKeyMetadata(const string &path_in_schema_dot) const;

	const string &GetAadPrefix() const {
		return aad_prefix;
	}
	bool GetSupplyAadPrefix() const {
		return supply_aad_prefix;
	}
	bool GetPlaintextFooter() const {
		return plaintext_footer;
	}
	bool HasAnyColumnKeys() const {
		return !column_keys.empty();
	}

	//! KMS / envelope-encryption accessors.
	const string &GetKmsClientName() const {
		return kms_client_name;
	}
	bool HasKmsClient() const {
		return !kms_client_name.empty();
	}
	//! Returns true if any master-key id has been configured (for footer or any column).
	bool HasAnyMasterKeyIds() const {
		return !footer_master_key_id.empty() || !column_master_key_ids.empty();
	}
	const string &GetFooterMasterKeyId() const {
		return footer_master_key_id;
	}
	//! Returns master key id for the given column path, or empty string if none.
	const string &GetColumnMasterKeyId(const string &path_in_schema_dot) const;
	bool GetDoubleWrapping() const {
		return double_wrapping;
	}

	//! Mutable setters used after construction when the writer materializes DEKs via KMS.
	void SetFooterKeyBytes(string key_bytes) {
		footer_key = std::move(key_bytes);
	}
	void SetColumnKeyBytes(const string &path_in_schema_dot, string key_bytes) {
		column_keys[path_in_schema_dot] = std::move(key_bytes);
	}
	void SetColumnKeyMetadata(const string &path_in_schema_dot, string key_metadata) {
		column_key_metadata[path_in_schema_dot] = std::move(key_metadata);
	}
	//! Footer-level wrapped key metadata (stored in FileCryptoMetaData.key_metadata).
	void SetFooterKeyMetadata(string key_metadata) {
		footer_key_metadata = std::move(key_metadata);
	}
	const string &GetFooterKeyMetadata() const {
		return footer_key_metadata;
	}

public:
	void Serialize(Serializer &serializer) const;
	static shared_ptr<ParquetEncryptionConfig> Deserialize(Deserializer &deserializer);

private:
	//! The encryption key used for the footer (and for every column not listed in column_keys).
	string footer_key;
	//! Mapping from column path (dot-joined path_in_schema) to raw AES key bytes.
	unordered_map<string, string> column_keys;
	//! Mapping from column path to optional user-supplied key_metadata (opaque bytes).
	unordered_map<string, string> column_key_metadata;
	//! Optional user-supplied AAD prefix (empty if not configured).
	string aad_prefix;
	//! If true, aad_prefix is NOT stored in FileCryptoMetaData; readers must supply it externally.
	bool supply_aad_prefix = false;
	//! If true, write the footer as plaintext + GCM tag (PAR1 magic). Reader-side auto-detects.
	bool plaintext_footer = false;
	//! KMS / envelope-encryption fields (PR-4). When kms_client_name is non-empty, the writer
	//! materializes random DEKs and wraps them via the KmsClient of this name; the reader resolves
	//! DEKs from `key_metadata` fields via the same KmsClient.
	string kms_client_name;
	string footer_master_key_id;
	unordered_map<string, string> column_master_key_ids;
	//! Whether double-wrapping is enabled (PyArrow-compatible). Default false (single wrapping).
	bool double_wrapping = false;
	//! Footer-level wrapped key metadata (stored in FileCryptoMetaData.key_metadata).
	string footer_key_metadata;
};

class ParquetCrypto {
public:
	//! Encrypted modules
	static constexpr idx_t LENGTH_BYTES = 4;
	static constexpr idx_t NONCE_BYTES = 12;
	static constexpr idx_t TAG_BYTES = 16;

	//! Block size we encrypt/decrypt
	static constexpr idx_t CRYPTO_BLOCK_SIZE = 4096;
	static constexpr idx_t BLOCK_SIZE = 16;

	// Module types for encryption
	static constexpr int8_t FOOTER = 0;
	static constexpr int8_t COLUMN_METADATA = 1;
	static constexpr int8_t DATA_PAGE = 2;
	static constexpr int8_t DICTIONARY_PAGE = 3;
	static constexpr int8_t DATA_PAGE_HEADER = 4;
	static constexpr int8_t DICTIONARY_PAGE_HEADER = 5;
	static constexpr int8_t COLUMN_INDEX = 6;
	static constexpr int8_t OFFSET_INDEX = 7;
	static constexpr int8_t BLOOM_FILTER_HEADER = 8;
	static constexpr int8_t BLOOM_FILTER_BITSET = 9;

	// Standard AAD length for file
	static constexpr int32_t UNIQUE_FILE_ID_LEN = 8;
	// Maximum Parquet AAD suffix bytes
	static constexpr int32_t AAD_MAX_SUFFIX_BYTES = 7;

public:
	//! Decrypt and read a Thrift object from the transport protocol
	static uint32_t Read(TBase &object, TProtocol &iprot, const string &key, const EncryptionUtil &encryption_util_p,
	                     const CryptoMetaData &crypto_meta_data);
	//! Encrypt and write a Thrift object to the transport protocol.
	//! The optional crypto_meta_data carries the AAD (module + ordinals). When empty (IsEmpty()==true),
	//! encryption falls back to legacy no-AAD mode (used by pre-1.5.4 DuckDB-produced files).
	static uint32_t Write(const TBase &object, TProtocol &oprot, const string &key,
	                      const EncryptionUtil &encryption_util_p);
	static uint32_t Write(const TBase &object, TProtocol &oprot, const string &key,
	                      const EncryptionUtil &encryption_util_p, const CryptoMetaData &crypto_meta_data);
	//! Serialize + encrypt a Thrift object into a bytes buffer (used for encrypted_column_metadata).
	//! The resulting bytes have the exact PME layout: [len(4)][nonce(12)][ciphertext][tag(16)].
	static string EncryptToBuffer(const TBase &object, const string &key, const EncryptionUtil &encryption_util_p,
	                              const CryptoMetaData &crypto_meta_data);
	//! Read + decrypt a Thrift object from a bytes buffer (used for encrypted_column_metadata).
	static void DecryptFromBuffer(TBase &object, const string &buffer, const string &key,
	                              const EncryptionUtil &encryption_util_p, const CryptoMetaData &crypto_meta_data);
	//! Decrypt and read a buffer
	static uint32_t ReadData(TProtocol &iprot, const data_ptr_t buffer, const uint32_t buffer_size, const string &key,
	                         const EncryptionUtil &encryption_util_p, const CryptoMetaData &crypto_meta_data);
	//! Encrypt and write a buffer to a file (optionally with PME AAD).
	static uint32_t WriteData(TProtocol &oprot, const const_data_ptr_t buffer, const uint32_t buffer_size,
	                          const string &key, const EncryptionUtil &encryption_util_p);
	static uint32_t WriteData(TProtocol &oprot, const const_data_ptr_t buffer, const uint32_t buffer_size,
	                          const string &key, const EncryptionUtil &encryption_util_p,
	                          const CryptoMetaData &crypto_meta_data);

public:
	static void AddKey(ClientContext &context, const FunctionParameters &parameters);
	static bool ValidKey(const std::string &key);

public:
	static int8_t GetModuleHeader(const ColumnChunk &chunk, uint16_t page_ordinal);
	static int8_t GetModule(const ColumnChunk &chunk, PageType::type page_type, uint16_t page_ordinal);
	static int16_t GetFinalPageOrdinal(const ColumnChunk &chunk, uint8_t module, uint16_t page_ordinal);
	static void GenerateAdditionalAuthenticatedData(Allocator &allocator, CryptoMetaData &aad_crypto_metadata);
	static unique_ptr<ParquetAdditionalAuthenticatedData> GenerateFooterAAD(Allocator &allocator,
	                                                                        const std::string &unique_file_identifier);
};

} // namespace duckdb
