package com.projectgalen.lib.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@SuppressWarnings("unused")
public class Crypto {

    public static byte[] createSecretKeyDigestFromBytes(byte[] secretBytes) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(secretBytes);
    }

    @NotNull
    public static SecretKey createSecretKeyFromBytes(byte[] digestBytes) {
        return createSecretKeyFromDigest(digestBytes);
    }

    @NotNull
    public static SecretKeySpec createSecretKeyFromDigest(byte[] digest) {
        return new SecretKeySpec(digest, "AES");
    }

    @NotNull
    public static SecretKey createSharedSecret(@NotNull PrivateKey privateKey, @NotNull PublicKey publicKey) throws Exception {
        return createSecretKeyFromBytes(createSharedSecretDigest(privateKey, publicKey));
    }

    @NotNull
    public static SecretKey createSharedSecret(@NotNull PrivateKey privateKey, byte[] publicKeyBytes) throws Exception {
        return createSecretKeyFromBytes(createSharedSecretDigest(privateKey, publicKeyBytes));
    }

    public static byte[] createSharedSecretDigest(@NotNull PrivateKey privateKey, @NotNull String publicKeyStr) throws Exception {
        return createSharedSecretDigest(privateKey, Base64.getDecoder().decode(publicKeyStr));
    }

    public static byte[] createSharedSecretDigest(@NotNull PrivateKey privateKey, byte[] publicKeyBytes) throws Exception {
        return createSharedSecretDigest(privateKey, KeyFactory.getInstance("DH", "BC").generatePublic(new X509EncodedKeySpec(publicKeyBytes)));
    }

    public static byte[] createSharedSecretDigest(@NotNull PrivateKey privateKey, @NotNull PublicKey publicKey) throws Exception {
        KeyAgreement keyAgree = getKeyAgreement(privateKey);
        keyAgree.doPhase(publicKey, true);
        return createSecretKeyDigestFromBytes(keyAgree.generateSecret());
    }

    @NotNull
    public static String decryptData(@NotNull SecretKey secretKey, @NotNull IvParameterSpec iv, @NotNull String cipherText) throws Exception {
        return decryptData(secretKey, iv, Base64.getDecoder().decode(cipherText));
    }

    @NotNull
    public static String decryptData(@NotNull SecretKey secretKey, @NotNull IvParameterSpec iv, byte[] cipherTextData) throws Exception {
        Cipher c = Cipher.getInstance("AES/OFB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return new String(c.doFinal(cipherTextData), StandardCharsets.UTF_8);
    }

    @NotNull
    public static String decryptData(@NotNull SecretKey secretKey, @NotNull String cipherText) throws Exception {
        return decryptData(secretKey, Base64.getDecoder().decode(cipherText));
    }

    @NotNull
    public static String decryptData(@NotNull SecretKey secretKey, byte[] cipherTextData) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, secretKey);
        return new String(c.doFinal(cipherTextData), StandardCharsets.UTF_8);
    }

    @NotNull
    public static String encryptData(@NotNull SecretKey secretKey, @NotNull IvParameterSpec iv, @NotNull String plainText) throws Exception {
        return encryptData(secretKey, iv, plainText.getBytes(StandardCharsets.UTF_8));
    }

    @NotNull
    public static String encryptData(@NotNull SecretKey secretKey, @NotNull IvParameterSpec iv, byte[] plainTextData) throws Exception {
        Cipher c = Cipher.getInstance("AES/OFB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return Base64.getEncoder().encodeToString(c.doFinal(plainTextData));
    }

    @NotNull
    public static String encryptData(@NotNull SecretKey secretKey, @NotNull String plainText) throws Exception {
        return encryptData(secretKey, plainText.getBytes(StandardCharsets.UTF_8));
    }

    @NotNull
    public static String encryptData(@NotNull SecretKey secretKey, byte[] plainTextData) throws Exception {
        Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, secretKey);
        return Base64.getEncoder().encodeToString(c.doFinal(plainTextData));
    }

    @NotNull
    public static IvParameterSpec generateIv() {
        return new IvParameterSpec(getRandom(16));
    }

    @NotNull
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
        keyGen.initialize(2048);
        return keyGen.genKeyPair();
    }

    @NotNull
    public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    @NotNull
    public static String getBase64EncodedPublicKey(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    @NotNull
    public static String getBase64EncodedSecretKey(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    @NotNull
    public static KeyAgreement getKeyAgreement(@NotNull PrivateKey privateKey) throws Exception {
        KeyAgreement keyAgree = KeyAgreement.getInstance("DH", "BC");
        keyAgree.init(privateKey);
        return keyAgree;
    }

    public static Provider getProvider() {
        return Security.getProvider("BC");
    }

    public static byte[] getRandom(int size) {
        byte[] iv = new byte[size];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}
