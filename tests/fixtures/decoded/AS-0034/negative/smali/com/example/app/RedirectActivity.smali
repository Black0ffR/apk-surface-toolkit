.class public Lcom/example/app/RedirectActivity;
.super Landroid/app/Activity;

.method public safe()V
    .locals 2
    new-instance v0, Landroid/content/Intent;
    invoke-direct {v0}, Landroid/content/Intent;-><init>()V
    invoke-virtual {p0, v0}, Lcom/example/app/RedirectActivity;->startActivity(Landroid/content/Intent;)V
    return-void
.end method
