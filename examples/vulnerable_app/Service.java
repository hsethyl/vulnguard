import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Statement;

public class Service {
    void run(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
    }

    void query(Statement stmt, String id) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE id=" + id);
    }

    void hash() throws Exception {
        MessageDigest.getInstance("MD5");
    }

    Object load(ObjectInputStream in) throws Exception {
        return in.readObject();
    }
}
