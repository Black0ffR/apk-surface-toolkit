.class public Lcom/example/app/Entry;
.super Ljava/lang/Object;

.method public entry()V
    .locals 2
    const-string v0, "about:blank"
    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
