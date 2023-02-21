package com.projectgalen.lib.crypto;

import com.projectgalen.lib.utils.PGResourceBundle;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

public class PublicKeyInfo {
    private static final PGResourceBundle msgs = PGResourceBundle.getXMLPGBundle("com.projectgalen.lib.crypto.crypto_messages");

    protected @NotNull String publicKey;
    protected @NotNull String iv;

    public PublicKeyInfo(@NotNull String publicKey, @NotNull String iv) {
        this.publicKey = publicKey;
        this.iv        = iv;
    }

    public @Override boolean equals(@Nullable Object o) {
        return ((this == o) || ((o instanceof PublicKeyInfo) && _equals((PublicKeyInfo)o)));
    }

    public @Override int hashCode() {
        return Objects.hash(publicKey, iv);
    }

    public @Override String toString() {
        return msgs.format("to.str.public_key_info", publicKey, iv);
    }

    public @NotNull String getIv() {
        return iv;
    }

    public @NotNull String getPublicKey() {
        return publicKey;
    }

    private boolean _equals(@NotNull PublicKeyInfo that) {
        return publicKey.equals(that.publicKey) && iv.equals(that.iv);
    }
}
