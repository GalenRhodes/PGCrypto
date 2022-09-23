package com.projectgalen.lib.crypto;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

public class PublicKeyInfo {
    protected @NotNull String publicKey;
    protected @NotNull String iv;

    public PublicKeyInfo(@NotNull String publicKey, @NotNull String iv) {
        this.publicKey = publicKey;
        this.iv        = iv;
    }

    public @NotNull String getIv() {
        return iv;
    }

    public @NotNull String getPublicKey() {
        return publicKey;
    }

    public @Override int hashCode() {
        return Objects.hash(publicKey, iv);
    }

    public @Override boolean equals(@Nullable Object o) {
        return ((this == o) || ((o instanceof PublicKeyInfo) && _equals((PublicKeyInfo)o)));
    }

    private boolean _equals(@NotNull PublicKeyInfo that) {
        return publicKey.equals(that.publicKey) && iv.equals(that.iv);
    }
}
