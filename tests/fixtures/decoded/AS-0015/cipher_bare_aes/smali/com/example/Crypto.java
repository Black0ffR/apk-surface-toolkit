package com.example;

public class Crypto {
    public byte[] encrypt(byte[] data, byte[] key) throws Exception {
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
        return c.doFinal(data);
    }
}
