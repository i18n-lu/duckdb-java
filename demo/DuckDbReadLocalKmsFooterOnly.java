// 方向 C 的 Java 读端 (LocalKMS, footer-only)：读 PyArrow 用 footer-only 加密的 PME parquet。
// 用法: java --class-path <pme-jar> DuckDbReadLocalKmsFooterOnly.java <in.parquet>
// 对应: PME-USAGE.md §4.2 footer-only 变体
import java.sql.*;
import java.util.Properties;

public class DuckDbReadLocalKmsFooterOnly {

    // ⚠️ 必须与 pyarrow_localkms.py 的 MASTER_KEYS['mk_footer'] 完全一致
    private static final String KMS = "local";
    private static final String MK_FOOTER = "mk_footer";
    private static final String MK_FOOTER_BYTES = "01234567891123450123456789112345";

    public static void main(String[] args) throws Exception {
        if (args.length != 1) { System.err.println("用法: DuckDbReadLocalKmsFooterOnly <in.parquet>"); System.exit(64); }
        String inPath = args[0];

        Properties props = new Properties();
        props.setProperty("allow_unsigned_extensions", "true");

        try (Connection c = DriverManager.getConnection("jdbc:duckdb:", props);
             Statement s = c.createStatement()) {
            s.execute("SET force_mbedtls_unsafe = 'true'");
            s.execute("PRAGMA add_parquet_key('" + MK_FOOTER + "', '" + MK_FOOTER_BYTES + "')");
            s.execute("PRAGMA register_local_kms('" + KMS + "')");

            // footer-only (PyArrow 17 变体)：pyarrow 把所有列挂到同一个 footer mkid 下，
            // 产物仍有 3 条 column key_metadata（outer-JSON masterKeyID=mk_footer），
            // duckdb-java 读时必须声明 column_master_key_ids 三列都用 mk_footer。
            String sql = "SELECT * FROM read_parquet('" + inPath.replace("'", "''") + "',"
                    + " encryption_config = {"
                    + "   kms_client:'" + KMS + "',"
                    + "   footer_master_key_id:'" + MK_FOOTER + "',"
                    + "   column_master_key_ids:{id:'" + MK_FOOTER + "', name:'" + MK_FOOTER + "', score:'" + MK_FOOTER + "'}"
                    + " })";
            System.out.println("[java-read-fo] SQL: " + sql);

            long n = 0;
            try (ResultSet rs = s.executeQuery(sql)) {
                int cols = rs.getMetaData().getColumnCount();
                StringBuilder h = new StringBuilder("[java-read-fo] cols:");
                for (int i = 1; i <= cols; i++)
                    h.append(' ').append(rs.getMetaData().getColumnLabel(i))
                     .append('(').append(rs.getMetaData().getColumnTypeName(i)).append(')');
                System.out.println(h);
                while (rs.next()) {
                    StringBuilder row = new StringBuilder("[java-read-fo] row:");
                    for (int i = 1; i <= cols; i++) row.append(' ').append(rs.getString(i));
                    System.out.println(row);
                    n++;
                }
            }
            System.out.println("[java-read-fo] total rows = " + n);
            if (n == 0) { System.err.println("[FAIL] 读到 0 行"); System.exit(1); }
        }
        System.out.println("[OK] PyArrow(footer-only) → DuckDB-Java 解密成功 ✅");
    }
}
