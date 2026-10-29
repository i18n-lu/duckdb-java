// 方向 A 的 Java 读端 (LocalKMS)：读 PyArrow 用 LocalKmsClient 加密的 PME parquet。
// 用法: java --class-path <pme-jar> DuckDbReadLocalKms.java <in.parquet>
// 对应: PME-USAGE.md §4.2
import java.sql.*;
import java.util.Properties;

public class DuckDbReadLocalKms {

    // ⚠️ 必须与 pyarrow_localkms.py 的 MASTER_KEYS/COLUMN_MASTER_KEYS 完全一致
    private static final String KMS = "local";
    private static final String[][] MK = {
        {"mk_footer",    "01234567891123450123456789112345"},
        {"mk_col_id",    "0123456789abcdef0123456789abcdef"},
        {"mk_col_name",  "fedcba9876543210fedcba9876543210"},
        {"mk_col_score", "7A2EeF5BcD6A4CaE88BbbFABfbF4cF77"},
    };

    public static void main(String[] args) throws Exception {
        if (args.length != 1) { System.err.println("用法: DuckDbReadLocalKms <in.parquet>"); System.exit(64); }
        String inPath = args[0];

        Properties props = new Properties();
        props.setProperty("allow_unsigned_extensions", "true");

        try (Connection c = DriverManager.getConnection("jdbc:duckdb:", props);
             Statement s = c.createStatement()) {
            s.execute("SET force_mbedtls_unsafe = 'true'");
            for (String[] kv : MK) s.execute("PRAGMA add_parquet_key('" + kv[0] + "', '" + kv[1] + "')");
            s.execute("PRAGMA register_local_kms('" + KMS + "')");

            String sql = "SELECT * FROM read_parquet('" + inPath.replace("'", "''") + "',"
                    + " encryption_config = {"
                    + "   kms_client: '" + KMS + "',"
                    + "   footer_master_key_id: 'mk_footer',"
                    + "   column_master_key_ids: {id: 'mk_col_id', name: 'mk_col_name', score: 'mk_col_score'}"
                    + " })";
            System.out.println("[java-read] SQL: " + sql);

            long n = 0;
            try (ResultSet rs = s.executeQuery(sql)) {
                int cols = rs.getMetaData().getColumnCount();
                StringBuilder h = new StringBuilder("[java-read] cols:");
                for (int i = 1; i <= cols; i++)
                    h.append(' ').append(rs.getMetaData().getColumnLabel(i))
                     .append('(').append(rs.getMetaData().getColumnTypeName(i)).append(')');
                System.out.println(h);
                while (rs.next()) {
                    StringBuilder row = new StringBuilder("[java-read] row:");
                    for (int i = 1; i <= cols; i++) row.append(' ').append(rs.getString(i));
                    System.out.println(row);
                    n++;
                }
            }
            System.out.println("[java-read] total rows = " + n);
            if (n == 0) { System.err.println("[FAIL] 读到 0 行"); System.exit(1); }
        }
        System.out.println("[OK] PyArrow → DuckDB-Java 解密成功 ✅");
    }
}
