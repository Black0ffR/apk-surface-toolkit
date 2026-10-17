package com.example;

public class Crypto {
    public byte[] encrypt(byte[] data, byte[] key) throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
        return c.doFinal(data);
    }
}
