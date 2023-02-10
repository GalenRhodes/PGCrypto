package com.projectgalen.lib.crypto;

import com.projectgalen.lib.utils.PGProperties;
import com.projectgalen.lib.utils.U;
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
public final class Crypto {

    private static final PGProperties props = PGProperties.getXMLProperties("crypto_settings.xml", Crypto.class);

    public static final int    AES_KEY_LENGTH             = props.getInt("crypto.aes.key_length");
    public static final int    DIFFIE_HELLMAN_KEY_LENGTH  = props.getInt("crypto.diffie_hellman.key_length");
    public static final int    IV_LENGTH                  = props.getInt("crypto.iv.length");
    public static final String AES_ALGORITHM              = props.getProperty("crypto.aes.algorithm");
    public static final String AES_TRANSFORMATION_NO_IV   = props.getProperty("crypto.aes.transformation.no_iv");
    public static final String AES_TRANSFORMATION_WITH_IV = props.getProperty("crypto.aes.transformation.with_iv");
    public static final String BOUNCY_CASTLE_PROVIDER     = props.getProperty("crypto.bouncy-castle.provider");
    public static final String DIFFIE_HELLMAN_ALGORITHM   = props.getProperty("crypto.diffie_hellman.algorithm");

    private final IvParameterSpec iv;
    private final SecretKey       secretKey;

    public Crypto(@NotNull DiffieHellmanHandshakeDelegate delegate) throws Exception {
        KeyPair       keyPair       = generateKeyPair();
        PublicKeyInfo publicKeyInfo = delegate.getPublicKeyInfo(getBase64EncodedPublicKey(keyPair));
        secretKey = createSharedSecret(keyPair.getPrivate(), publicKeyInfo.getPublicKey());
        iv        = new IvParameterSpec(decryptBytes(secretKey, publicKeyInfo.getIv()));
    }

    public @NotNull String decrypt(@NotNull String base64EncodedCipherText) throws GeneralSecurityException {
        return decryptData(secretKey, iv, base64EncodedCipherText);
    }

    public byte @NotNull [] decryptBytes(@NotNull String base64EncodedCipherText) throws GeneralSecurityException {
        return decryptBytes(secretKey, iv, base64EncodedCipherText);
    }

    public @NotNull String encrypt(@NotNull String str) throws GeneralSecurityException {
        return encryptData(secretKey, iv, str);
    }

    public @NotNull String encrypt(byte @NotNull [] data) throws GeneralSecurityException {
        return encryptData(secretKey, iv, data);
    }

    public static byte @NotNull [] createSHA256Digest(byte @NotNull [] secretBytes) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256").digest(secretBytes);
    }

    public static @NotNull SecretKeySpec createSecretKeyFromDigest(byte @NotNull [] digest) {
        return new SecretKeySpec(digest, AES_ALGORITHM);
    }

    public static @NotNull SecretKey createSecreteKeyFromDigest(String encDigest) {
        return createSecretKeyFromDigest(U.base64Decode(encDigest));
    }

    public static @NotNull SecretKey createSharedSecret(@NotNull PrivateKey privateKey, @NotNull String strPublicKeyEnc) throws GeneralSecurityException {
        return createSecretKeyFromDigest(createSharedSecretDigest(privateKey, strPublicKeyEnc));
    }

    public static @NotNull SecretKey createSharedSecret(@NotNull PrivateKey privateKey, @NotNull PublicKey publicKey) throws GeneralSecurityException {
        return createSecretKeyFromDigest(createSharedSecretDigest(privateKey, publicKey));
    }

    public static @NotNull SecretKey createSharedSecret(@NotNull PrivateKey privateKey, byte @NotNull [] publicKeyBytes) throws GeneralSecurityException {
        return createSecretKeyFromDigest(createSharedSecretDigest(privateKey, publicKeyBytes));
    }

    public static byte @NotNull [] createSharedSecretDigest(@NotNull PrivateKey privateKey, @NotNull String publicKeyStr) throws GeneralSecurityException {
        return createSharedSecretDigest(privateKey, U.base64Decode(publicKeyStr));
    }

    public static byte @NotNull [] createSharedSecretDigest(@NotNull PrivateKey privateKey, byte @NotNull [] publicKeyBytes) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance(DIFFIE_HELLMAN_ALGORITHM, BOUNCY_CASTLE_PROVIDER);
        return createSharedSecretDigest(privateKey, keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes)));
    }

    public static byte @NotNull [] createSharedSecretDigest(@NotNull PrivateKey privateKey, @NotNull PublicKey publicKey) throws GeneralSecurityException {
        KeyAgreement keyAgree = getKeyAgreement(privateKey);
        keyAgree.doPhase(publicKey, true);
        return createSHA256Digest(keyAgree.generateSecret());
    }

    public static byte @NotNull [] decryptBytes(@NotNull SecretKey secretKey, byte @NotNull [] cipherTextData) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(AES_TRANSFORMATION_NO_IV);
        c.init(Cipher.DECRYPT_MODE, secretKey);
        return c.doFinal(cipherTextData);
    }

    public static byte @NotNull [] decryptBytes(@NotNull SecretKey secretKey, @NotNull String cipherText) throws GeneralSecurityException {
        return decryptBytes(secretKey, U.base64Decode(cipherText));
    }

    public static byte @NotNull [] decryptBytes(@NotNull SecretKey secretKey, @NotNull IvParameterSpec iv, @NotNull String cipherText) throws GeneralSecurityException {
        return decryptBytes(secretKey, iv, U.base64Decode(cipherText));
    }

    public static byte @NotNull [] decryptBytes(@NotNull SecretKey secretKey, @NotNull IvParameterSpec iv, byte @NotNull [] cipherTextData) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(AES_TRANSFORMATION_WITH_IV);
        c.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return c.doFinal(cipherTextData);
    }

    public static @NotNull String decryptData(@NotNull SecretKey secretKey, @NotNull IvParameterSpec iv, @NotNull String cipherText) throws GeneralSecurityException {
        return decryptData(secretKey, iv, U.base64Decode(cipherText));
    }

    public static @NotNull String decryptData(@NotNull SecretKey secretKey, @NotNull IvParameterSpec iv, byte @NotNull [] cipherTextData) throws GeneralSecurityException {
        return new String(decryptBytes(secretKey, iv, cipherTextData), StandardCharsets.UTF_8);
    }

    public static @NotNull String decryptData(@NotNull SecretKey secretKey, @NotNull String cipherText) throws GeneralSecurityException {
        return decryptData(secretKey, U.base64Decode(cipherText));
    }

    public static @NotNull String decryptData(@NotNull SecretKey secretKey, byte @NotNull [] cipherTextData) throws GeneralSecurityException {
        return new String(decryptBytes(secretKey, cipherTextData), StandardCharsets.UTF_8);
    }

    public static @NotNull String encryptData(@NotNull SecretKey secretKey, @NotNull IvParameterSpec iv, @NotNull String plainText) throws GeneralSecurityException {
        return encryptData(secretKey, iv, plainText.getBytes(StandardCharsets.UTF_8));
    }

    public static @NotNull String encryptData(@NotNull SecretKey secretKey, @NotNull IvParameterSpec iv, byte @NotNull [] plainTextData) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(AES_TRANSFORMATION_WITH_IV);
        c.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return Base64.getEncoder().encodeToString(c.doFinal(plainTextData));
    }

    public static @NotNull String encryptData(@NotNull SecretKey secretKey, @NotNull String plainText) throws GeneralSecurityException {
        return encryptData(secretKey, plainText.getBytes(StandardCharsets.UTF_8));
    }

    public static @NotNull String encryptData(@NotNull SecretKey secretKey, byte @NotNull [] plainTextData) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(AES_TRANSFORMATION_NO_IV);
        c.init(Cipher.ENCRYPT_MODE, secretKey);
        return Base64.getEncoder().encodeToString(c.doFinal(plainTextData));
    }

    public static @NotNull IvParameterSpec generateIv() {
        return new IvParameterSpec(getRandom(IV_LENGTH));
    }

    public static @NotNull KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(DIFFIE_HELLMAN_ALGORITHM, BOUNCY_CASTLE_PROVIDER);
        keyGen.initialize(DIFFIE_HELLMAN_KEY_LENGTH);
        return keyGen.genKeyPair();
    }

    public static @NotNull SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGenerator.init(AES_KEY_LENGTH);
        return keyGenerator.generateKey();
    }

    public static @NotNull String getBase64EncodedPublicKey(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public static @NotNull String getBase64EncodedSecretKey(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static @NotNull KeyAgreement getKeyAgreement(@NotNull PrivateKey privateKey) throws GeneralSecurityException {
        KeyAgreement keyAgree = KeyAgreement.getInstance(DIFFIE_HELLMAN_ALGORITHM, BOUNCY_CASTLE_PROVIDER);
        keyAgree.init(privateKey);
        return keyAgree;
    }

    public static @NotNull Provider getProvider() {
        return Security.getProvider(BOUNCY_CASTLE_PROVIDER);
    }

    public static byte @NotNull [] getRandom(int size) {
        byte @NotNull [] iv = new byte[size];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}
