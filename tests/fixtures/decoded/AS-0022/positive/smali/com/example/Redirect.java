package com.example;

public class Redirect {
    public String target() {
        String next = getIntent().getStringExtra("next");
        return next;
    }
}
