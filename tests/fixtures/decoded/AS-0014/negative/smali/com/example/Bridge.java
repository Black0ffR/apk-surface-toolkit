package com.example;

public class Bridge {
    public void wire(WebView webView) {
        webView.addJsCallback(new Bridge(), "B");
    }
}
