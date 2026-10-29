// 方向 B 的 Java 写端 (LocalKMS)：**column-level KMS 加密**，footer + 每列独立 DEK。
// 用法: java --class-path <pme-jar> DuckDbWriteLocalKms.java <out.parquet>
// 对应: PME-USAGE.md §4.2
import java.sql.*;
import java.util.Properties;

public class DuckDbWriteLocalKms {

    // ⚠️ 必须与 pyarrow_localkms.py 的 MASTER_KEYS 完全一致
    private static final String KMS = "local";
    private static final String[][] MK = {
        {"mk_footer",    "01234567891123450123456789112345"},
        {"mk_col_id",    "0123456789abcdef0123456789abcdef"},
        {"mk_col_name",  "fedcba9876543210fedcba9876543210"},
        {"mk_col_score", "7A2EeF5BcD6A4CaE88BbbFABfbF4cF77"},
    };

    public static void main(String[] args) throws Exception {
        if (args.length != 1) { System.err.println("用法: DuckDbWriteLocalKms <out.parquet>"); System.exit(64); }
        String out = args[0];

        Properties props = new Properties();
        props.setProperty("allow_unsigned_extensions", "true");

        try (Connection c = DriverManager.getConnection("jdbc:duckdb:", props);
             Statement s = c.createStatement()) {
            s.execute("SET force_mbedtls_unsafe = 'true'");
            for (String[] kv : MK) s.execute("PRAGMA add_parquet_key('" + kv[0] + "', '" + kv[1] + "')");
            s.execute("PRAGMA register_local_kms('" + KMS + "')");

            // column-level KMS 加密：footer DEK + 每列专属 DEK，Parquet 文件写 1 条 footer key_metadata
            // + 3 条 column key_metadata（后者嵌在加密的 FileMetaData 里）
            String sql = "COPY (SELECT * FROM (VALUES "
                    + "(1,'alice',3.14),(2,'bob',2.72),(3,'carol',-1.00),(4,'dave',0.5),(5,'eve',42.0)"
                    + ") AS t(id,name,score)) "
                    + "TO '" + out.replace("'", "''") + "' "
                    + "(ENCRYPTION_CONFIG {"
                    + "   kms_client:'" + KMS + "',"
                    + "   footer_master_key_id:'mk_footer',"
                    + "   column_master_key_ids:{id:'mk_col_id', name:'mk_col_name', score:'mk_col_score'}"
                    + " })";
            System.out.println("[java-write] SQL: " + sql);
            s.execute(sql);
            System.out.println("[java-write] wrote: " + out);

            // 自回读
            String readSql = "SELECT count(*) FROM read_parquet('" + out.replace("'", "''") + "',"
                    + " encryption_config = {"
                    + "   kms_client:'" + KMS + "',"
                    + "   footer_master_key_id:'mk_footer',"
                    + "   column_master_key_ids:{id:'mk_col_id', name:'mk_col_name', score:'mk_col_score'}"
                    + " })";
            try (ResultSet rs = s.executeQuery(readSql)) {
                if (rs.next()) {
                    long n = rs.getLong(1);
                    System.out.println("[java-write] self-roundtrip rows = " + n);
                    if (n != 5) { System.err.println("[FAIL] 自回读行数不是 5"); System.exit(1); }
                }
            }
        }
        System.out.println("[OK] DuckDB-Java 写完成，可被 PyArrow 读");
    }
}
