.class public Lcom/example/app/MainActivity;
.super Landroid/app/Activity;

.method public show()V
    .locals 2
    const-string v0, "https://example.com"
    invoke-virtual {p0, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
