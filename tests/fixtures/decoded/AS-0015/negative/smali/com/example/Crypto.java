package com.example;

public class Crypto {
    public byte[] encrypt(byte[] data, byte[] key) throws Exception {
        javax.crypto.Cipher gcm = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        javax.crypto.Cipher cbc = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
        java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
        javax.crypto.Cipher rsa = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        return gcm.doFinal(data);
    }
}
