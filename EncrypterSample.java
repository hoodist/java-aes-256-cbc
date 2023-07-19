import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class EncrypterSample {
    private String algorithm = "AES/CBC/PKCS5Padding";
    private String key = "123456789-123456789-123456789-12";

    public static void main(String[] args) throws Exception {
        EncrypterSample encrypter = new EncrypterSample();
        String encrypted = encrypter.encrypt("{\"test\":\"hello\"}", false);
        String decrypted = encrypter.decrypt(encrypted, false);
    }

    public String encrypt(String value, boolean serialize) throws Exception {
        byte[] iv = generateRandomBytes(getCipherIVLength());

        Cipher cipher = Cipher.getInstance(algorithm);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));

        byte[] encryptedValue = cipher.doFinal(serialize ? serializeValue(value) : value.getBytes(StandardCharsets.UTF_8));

        String json = buildJson(iv, encryptedValue);
        System.out.println("Encrypt Data Structure: " + json);

        String encrypted = encodeBase64(json.getBytes(StandardCharsets.UTF_8));
        System.out.println("Encrypted : " + encrypted);

        return encrypted;
    }

    public String decrypt(String payload, boolean unserialize) throws Exception {
        String jsonPayload = new String(decodeBase64(payload), StandardCharsets.UTF_8);
        System.out.println(jsonPayload);

        String ivBase64 = getJsonValue(jsonPayload, "iv");
        String encryptedValueBase64 = getJsonValue(jsonPayload, "value");

        byte[] iv = decodeBase64(ivBase64);
        byte[] encryptedValue = decodeBase64(encryptedValueBase64);

        Cipher cipher = Cipher.getInstance(algorithm);
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(), "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

        byte[] decryptedValue = cipher.doFinal(encryptedValue);

        String decrypted = unserialize ? deserializeValue(decryptedValue) : new String(decryptedValue, StandardCharsets.UTF_8);
        System.out.println("Decrypted: " + decrypted);

        return decrypted;
    }

    private int getCipherIVLength() {
        try {
            return Cipher.getInstance(algorithm).getBlockSize();
        } catch (Exception e) {
            throw new RuntimeException("Error retrieving cipher's IV length.", e);
        }
    }

    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    private byte[] serializeValue(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private String deserializeValue(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private String encodeBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private byte[] decodeBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    private String getJsonValue(String json, String key) {
        int startIndex = json.indexOf("\"" + key + "\":\"");
        if (startIndex == -1) {
            return "";
        }

        int endIndex = json.indexOf("\"", startIndex + key.length() + 4);
        if (endIndex == -1) {
            return "";
        }

        return json.substring(startIndex + 1 + key.length() + 3, endIndex);
    }

    private String buildJson(byte[] iv, byte[] value) {
        return String.format("{\"iv\":\"%s\",\"value\":\"%s\",\"mac\":\"\",\"tag\":\"\"}",
                encodeBase64(iv), encodeBase64(value));
    }
}
