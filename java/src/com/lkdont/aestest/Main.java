package com.lkdont.aestest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * 主函数
 * <p/>
 * Created by lkdont on 10/5/16.
 */
public class Main {

    public static void main(String[] args) {
        String content = "Hello World!!!";
        String password = "12345678";

//        String enContent0 = AESUtil_0.encrypt(content, password);
//        System.out.println("AESUtil_0 enContent = " + enContent0);
//
//        String deContent0 = AESUtil_0.decrypt(enContent0, password);
//        System.out.println("AESUtil_0 deContent = " + deContent0);

        byte[] salt = AESUtil_1.createSalt();

        if (salt != null) {
            String enContent1 = AESUtil_1.encrypt(content, password, salt);
            System.out.println("AESUtil_1 enContent = " + enContent1);

            String deContent1 = AESUtil_1.decrypt(enContent1, password, salt);
            System.out.println("AESUtil_1 deContent = " + deContent1);

            // 将salt和加密内容发送出去
            String saltStr = AESUtil_1.parseByte2HexStr(salt);
            System.out.println("AESUtil_1 saltStr = " + saltStr);
            postContent(saltStr + enContent1);

        } else {
            System.err.println("salt == null, 不能加密/解密");
        }
    }

    private static void postContent(String content) {
        HttpURLConnection connection = null;
        try {
            URL url = new URL("http://localhost:8080/aestest.php");
            connection = (HttpURLConnection) url.openConnection();

            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("POST");

            // post请求的参数
            String data = "content=" + content;
            // 获得一个输出流,向服务器写数据,默认情况下,系统不允许向服务器输出内容
            OutputStream out = connection.getOutputStream();// 获得一个输出流,向服务器写数据
            out.write(data.getBytes());
            out.flush();
            out.close();

            int responseCode = connection.getResponseCode();// 调用此方法就不必再使用conn.connect()方法
            if (responseCode == 200) {
                InputStream is = connection.getInputStream();
                System.out.println("\n访问成功 : \n" + getStringFromInputStream(is));
            } else {
                System.err.println("\n访问失败 : \n" + responseCode);
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static String getStringFromInputStream(InputStream is)
            throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int len = -1;
        while ((len = is.read(buffer)) != -1) {
            os.write(buffer, 0, len);
        }
        is.close();
        String state = os.toString();
        os.close();
        return state;
    }
}
