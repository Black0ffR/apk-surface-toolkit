.class public Lcom/example/app/RedirectActivity;
.super Landroid/app/Activity;

.method public onNewIntent(Landroid/content/Intent;)V
    .locals 2
    const-string v1, "redirect"
    invoke-virtual {p1, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    invoke-virtual {p0, v0}, Landroid/content/Intent;->setClass(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;
    return-void
.end method
