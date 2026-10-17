package com.example;

public class Crypto {
    public byte[] digest(byte[] data) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
        return md.digest(data);
    }
}
