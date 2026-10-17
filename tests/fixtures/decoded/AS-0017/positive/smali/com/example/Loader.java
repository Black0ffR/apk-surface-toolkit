package com.example;

public class Loader {
    public Object load(String path) throws Exception {
        DexClassLoader loader = new DexClassLoader(path, null, null, getClass().getClassLoader());
        return loader.loadClass("com.example.Plugin");
    }
}
