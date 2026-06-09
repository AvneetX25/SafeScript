import java.sql.*;
import java.io.*;

public class VulnerableSample {

    // Vulnerability 1: Hardcoded credentials (Semgrep: java.lang.security)
    private static final String PASSWORD = "admin123";
    private static final String DB_URL = "jdbc:mysql://localhost/db?user=root&password=root123";

    // Vulnerability 2: SQL Injection — string concatenation in query
    public static void getUser(String username) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL);
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        ResultSet rs = stmt.executeQuery(query);
    }

    // Vulnerability 3: Command injection — Runtime.exec with user input
    public static void runCommand(String userInput) throws Exception {
        Runtime runtime = Runtime.getRuntime();
        runtime.exec("ls " + userInput);
    }

    // Clean method — should NOT be flagged
    public static int safeAdd(int a, int b) {
        return a + b;
    }

    // Vulnerability 4: Weak hashing algorithm (MD5)
    public static void hashPassword(String password) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
    }
}