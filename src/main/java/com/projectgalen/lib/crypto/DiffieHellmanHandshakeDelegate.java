package com.projectgalen.lib.crypto;

import org.jetbrains.annotations.NotNull;

public interface DiffieHellmanHandshakeDelegate {
    @NotNull PublicKeyInfo getPublicKeyInfo(@NotNull String strPublicKey) throws Exception;
}
