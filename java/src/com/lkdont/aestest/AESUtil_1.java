package com.lkdont.aestest;

import com.sun.istack.internal.NotNull;
import com.sun.istack.internal.Nullable;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * AES加密/解密工具。
 * 使用{@link #decrypt(String, String, byte[])}方法加密的内容能在php工程中解密。
 * <p/>
 * Created by lkdont on 10/5/16.
 */
public class AESUtil_1 {

    private static final String DEF_CHARSET = "utf-8";
    private static final String CIPHER_STR = "AES/ECB/PKCS5Padding";

//    public static byte[] salt;

    /**
     * 生成salt, 用于对password进行处理。
     * 加密和解密时用到的salt必须一致, 否则解密不了。
     */
    @Nullable
    public static byte[] createSalt() {

        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            return salt;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    private static Key getKey(@NotNull String password, @NotNull byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        int iterations = 1000;
        int keySize = 128;

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keySize);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] bytes = factory.generateSecret(spec).getEncoded();

//        System.out.println("key bytes = " + AESUtil_1.parseByte2HexStr(bytes));

        return new SecretKeySpec(bytes, "AES");
    }

    /**
     * 加密方法
     *
     * @param content  要被加密的内容
     * @param password 密码
     * @return 被加密后的内容
     */
    @Nullable
    public static String encrypt(@NotNull String content, @NotNull String password, @NotNull byte[] salt) {

        try {

            Key key = getKey(password, salt);
            Cipher cipher = Cipher.getInstance(CIPHER_STR);// 创建密码器
            byte[] contentBytes = content.getBytes(DEF_CHARSET);
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(contentBytes);
            return parseByte2HexStr(result); // 加密

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 揭秘方法
     *
     * @param content  要被解密的内容
     * @param password 密码
     * @return 被解密后的内容
     */
    public static String decrypt(@NotNull String content, @NotNull String password, @NotNull byte[] salt) {

        try {

            Key key = getKey(password, salt);
            Cipher cipher = Cipher.getInstance(CIPHER_STR);// 创建密码器
            cipher.init(Cipher.DECRYPT_MODE, key);// 初始化

            byte[] contentBytes = parseHexStr2Byte(content);
            if (contentBytes != null) {
                byte[] result = cipher.doFinal(contentBytes);
                return new String(result, DEF_CHARSET);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 将二进制转换成16进制
     */
    public static String parseByte2HexStr(@NotNull byte buf[]) {
        StringBuilder sb = new StringBuilder();
        for (byte aBuf : buf) {
            String hex = Integer.toHexString(aBuf & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            sb.append(hex.toUpperCase());
        }
        return sb.toString();
    }

    /**
     * 将16进制转换为二进制
     */
    private static byte[] parseHexStr2Byte(@NotNull String hexStr) throws NumberFormatException {

        int len = hexStr.length();
        if (len < 1)
            return null;

        int size = hexStr.length() / 2;
        byte[] result = new byte[size];
        for (int i = 0; i < size; i++) {
            int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
            int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
            result[i] = (byte) (high * 16 + low);
        }
        return result;
    }

}
