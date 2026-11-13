import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PasswordUtil {

    public static String generateSalt() {

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        return Base64.getEncoder().encodeToString(salt);
    }

    public static String hashPassword(
        String password, String saltText
    ) throws Exception {

        byte[] salt = Base64.getDecoder().decode(saltText);

        PBEKeySpec spec = new PBEKeySpec(
            password.toCharArray(),
            salt,
            120000,
            256
        );

        byte[] result = SecretKeyFactory
            .getInstance("PBKDF2WithHmacSHA256")
            .generateSecret(spec)
            .getEncoded();

        spec.clearPassword();

        return Base64.getEncoder().encodeToString(result);
    }

    public static boolean verifyPassword(
        String password,
        String salt,
        String savedHash
    ) throws Exception {

        String enteredHash = hashPassword(password, salt);

        return MessageDigest.isEqual(
            enteredHash.getBytes(java.nio.charset.StandardCharsets.UTF_8),
            savedHash.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
    }
}
