package com.example;

public class Bridge {
    public void wire(WebView webView) {
        webView.addJavascriptInterface(new Bridge(), "B");
    }
}
