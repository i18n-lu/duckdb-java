// 方向 D 的 Java 写端 (LocalKMS, footer-only)：footer-only KMS 加密，所有列共享 footer DEK。
// 用法: java --class-path <pme-jar> DuckDbWriteLocalKmsFooterOnly.java <out.parquet>
// 对应: PME-USAGE.md §4.2 footer-only 变体
import java.sql.*;
import java.util.Properties;

public class DuckDbWriteLocalKmsFooterOnly {

    // ⚠️ 必须与 pyarrow_localkms.py 的 MASTER_KEYS['mk_footer'] 完全一致
    private static final String KMS = "local";
    private static final String MK_FOOTER = "mk_footer";
    private static final String MK_FOOTER_BYTES = "01234567891123450123456789112345";

    public static void main(String[] args) throws Exception {
        if (args.length != 1) { System.err.println("用法: DuckDbWriteLocalKmsFooterOnly <out.parquet>"); System.exit(64); }
        String out = args[0];

        Properties props = new Properties();
        props.setProperty("allow_unsigned_extensions", "true");

        try (Connection c = DriverManager.getConnection("jdbc:duckdb:", props);
             Statement s = c.createStatement()) {
            s.execute("SET force_mbedtls_unsafe = 'true'");
            s.execute("PRAGMA add_parquet_key('" + MK_FOOTER + "', '" + MK_FOOTER_BYTES + "')");
            s.execute("PRAGMA register_local_kms('" + KMS + "')");

            // footer-only KMS 加密：Parquet 只写 1 条 footer key_metadata，所有列共享 footer DEK
            String sql = "COPY (SELECT * FROM (VALUES "
                    + "(1,'alice',3.14),(2,'bob',2.72),(3,'carol',-1.00),(4,'dave',0.5),(5,'eve',42.0)"
                    + ") AS t(id,name,score)) "
                    + "TO '" + out.replace("'", "''") + "' "
                    + "(ENCRYPTION_CONFIG {kms_client:'" + KMS + "', footer_master_key_id:'" + MK_FOOTER + "'})";
            System.out.println("[java-write-fo] SQL: " + sql);
            s.execute(sql);
            System.out.println("[java-write-fo] wrote: " + out);

            // 自回读校验
            String readSql = "SELECT count(*) FROM read_parquet('" + out.replace("'", "''") + "',"
                    + " encryption_config = {kms_client:'" + KMS + "', footer_master_key_id:'" + MK_FOOTER + "'})";
            try (ResultSet rs = s.executeQuery(readSql)) {
                if (rs.next()) {
                    long n = rs.getLong(1);
                    System.out.println("[java-write-fo] self-roundtrip rows = " + n);
                    if (n != 5) { System.err.println("[FAIL] 自回读行数不是 5"); System.exit(1); }
                }
            }
        }
        System.out.println("[OK] DuckDB-Java(footer-only) 写完成，可被 PyArrow 读");
    }
}
