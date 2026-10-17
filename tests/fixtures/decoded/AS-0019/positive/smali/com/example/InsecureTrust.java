package com.example;

public class BrokenTrustManager implements X509TrustManager {
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
    }
}
