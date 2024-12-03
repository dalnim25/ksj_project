import java.sql.*;

public class TestApp {
    public static void main(String[] args) {
        String userInput = "admin'; DROP TABLE users; --";
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/test", "user", "password");
            Statement stmt = conn.createStatement();
            
            // SQL Injection 취약점
            String query = "SELECT * FROM users WHERE username = '" + userInput + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                System.out.println(rs.getString("username"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
