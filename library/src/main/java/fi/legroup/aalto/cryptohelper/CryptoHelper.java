package fi.legroup.aalto.cryptohelper;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Simple utilities for encrypting strings.
 * Usage:
 * String secretKey = "hx/Tbx4Q8fTEc8sS65nxWg==";
 *
 * String encrypted = CryptoHelper.encrypt("Hello world!", secretKey);
 * String decrypted = CryptoHelper.decrypt(encrypted, secretKey);
 */
public class CryptoHelper {

    // Every Java implementation supports AES/CBC/PKCS5Padding encryption with at least 128-bit keys.
    public static final String ENCRYPT_ALGORITHM = "AES";
    public static final String ENCRYPT_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    public static final int ENCRYPT_KEY_BITS = 128;

    // 16 byte initialization vector is required by the above.
    public static final int IV_BYTES = 16;

    /**
     * Return the CRC32 checksum of `bytes`.
     */
    public static long crc32(byte[] bytes) {
        CRC32 crc = new CRC32();
        crc.update(bytes);
        return crc.getValue();
    }

    /**
     * Encode a string into bytes. Retrieve original string with `decode()`.
     * @return {@code crc32(utf8(value)) + utf8(value) }
     */
    public static byte[] encode(String value) throws GeneralSecurityException {
        try {
            // Store the string with UTF-8 encoding with the CRC32 checksum prepended to it.
            byte[] encoded = value.getBytes("UTF-8");
            long checksum = crc32(encoded);

            return ByteBuffer.allocate(encoded.length + 8)
                    .putLong(checksum).put(encoded).array();

        } catch (UnsupportedEncodingException e) {
            // Should happen only when UTF-8 encoding is not possible, so practically never.
            throw new GeneralSecurityException("Failed to encode value", e);
        }
    }

    /**
     * Decode bytes from `encode()` to a string.
     * @param value Must be the return value of `encode()`
     */
    public static String decode(byte[] value) throws GeneralSecurityException {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(value);
            if (buffer.remaining() < 8) {
                // Not enough data to read the checksum, must be corrupt or invalid.
                throw new GeneralSecurityException("Not enough data to decode");
            }

            // Split the bytes into the CRC32 checksum and UTF-8 encoded bytes.
            long checksum = buffer.getLong();
            byte[] encoded = new byte[buffer.remaining()];
            buffer.get(encoded);

            if (checksum != crc32(encoded)) {
                // If the calculated checksum differs from the stored data it is corrupted or not
                // the result of `encode()`.
                throw new GeneralSecurityException("Decoded unexpected data");
            }
            return new String(encoded, "UTF-8");

        } catch (UnsupportedEncodingException e) {
            // Should happen only when UTF-8 encoding is not possible, so practically never.
            throw new GeneralSecurityException("Failed to decode value", e);
        }
    }

    /**
     * Helper function for creating a Cipher object.
     * @param mode Cipher.ENCRYPT_MODE or Cipher.DECRYPT_MODE
     * @param secret Base64 encoded 128-bit secret.
     * @param iv Initialization vector, should be generated for encrypting and stored with the
     *           encrypted data. The stored IV is read and used for decrypting.
     *           See `generateIV()`
     */
    public static Cipher createCipher(int mode, String secret, byte[] iv) throws GeneralSecurityException {
        byte[] secretBytes = Base64.decode(secret, Base64.DEFAULT);

        // Technically not required but using larger or unusual key sizes is not universally
        // supported so better fail fast here than end up with interoperability problems.
        if (secretBytes.length * 8 != ENCRYPT_KEY_BITS) {
            throw new GeneralSecurityException("Expected " + ENCRYPT_KEY_BITS + " bit key");
        }

        // Initialize the cipher with the wanted parameters.
        SecretKeySpec keySpec = new SecretKeySpec(secretBytes, ENCRYPT_ALGORITHM);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(ENCRYPT_TRANSFORMATION);
        cipher.init(mode, keySpec, ivSpec);

        return cipher;
    }

    /**
     * Generate an initialization vector to encrypt with. Passable to `createCipher()`.
     */
    public static byte[] generateIV() {
        SecureRandom random = new SecureRandom();
        return random.generateSeed(IV_BYTES);
    }

    /**
     * Encrypt `value` using the `secret`. The original `value` can be retrieved using `decrypt()`
     * with the same secret.
     * @param value String to encrypt.
     * @param secret Secret 128-bit value to encrypt the data with.
     * @return {@code base64(IV + encrypt(encode(value), secret, IV)) }
     */
    public static String encrypt(String value, String secret) throws GeneralSecurityException {

        // Setup the cipher with randomly generated initialization vector.
        byte[] ivBytes = generateIV();
        Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, secret, ivBytes);

        // Encode the string into bytes and encrypt it.
        byte[] valueBytes = encode(value);
        byte[] encryptedBytes = cipher.doFinal(valueBytes);

        // Concatenate the initialization vector and the encrypted value.
        byte[] ivAndValueBytes = ByteBuffer.allocate(ivBytes.length + encryptedBytes.length)
                .put(ivBytes).put(encryptedBytes).array();

        // Base64 encode the result for storing as a string.
        return Base64.encodeToString(ivAndValueBytes, Base64.DEFAULT);
    }

    /**
     * Decrypt the result of `encrypt()` returning the original string.
     * @param encoded Must be the returned value from `encrypt()`
     * @param secret Secret 128-bit value to decrypt with.
     *               Must match the `secret` used when the string was encrypted.
     * @return {@code decode(decrypt(encoded, secret)) }
     */
    public static String decrypt(String encoded, String secret) throws GeneralSecurityException {

        // Base64 decode the concatenated initialization vector and encrypted data.
        byte[] ivAndValueBytes = Base64.decode(encoded, Base64.DEFAULT);
        ByteBuffer buffer = ByteBuffer.wrap(ivAndValueBytes);

        // Split to initialization vector and encrypted value bytes.
        byte[] ivBytes, encryptedBytes;
        try {
            ivBytes = new byte[IV_BYTES];
            buffer.get(ivBytes);
            encryptedBytes = new byte[buffer.remaining()];
            buffer.get(encryptedBytes);

        } catch (BufferUnderflowException e) {
            throw new GeneralSecurityException("Input too short", e);
        }

        // Decrypt the value. This might fail if the data is invalid.
        Cipher cipher = createCipher(Cipher.DECRYPT_MODE, secret, ivBytes);
        byte[] valueBytes = cipher.doFinal(encryptedBytes);
        if (valueBytes == null) {
            throw new GeneralSecurityException("Failed to decrypt");
        }

        // Decode the value. This might also fail since the checksum is checked here.
        return decode(valueBytes);
    }
}
