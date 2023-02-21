package com.projectgalen.lib.crypto;

import com.projectgalen.lib.utils.PGProperties;
import com.projectgalen.lib.utils.PGResourceBundle;
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

@SuppressWarnings({ "unused" })
public final class Crypto {

    private static final PGResourceBundle msgs  = PGResourceBundle.getXMLPGBundle("com.projectgalen.lib.crypto.crypto_messages");
    private static final PGProperties     props = PGProperties.getXMLProperties("crypto_settings.xml", Crypto.class);

    private final IvParameterSpec iv;
    private final SecretKey       secretKey;
    private final PublicKeyInfo   publicKeyInfo;
    private final KeyPair         keyPair;

    public Crypto(@NotNull DiffieHellmanHandshakeDelegate delegate) throws Exception {
        keyPair       = generateKeyPair();
        publicKeyInfo = delegate.getPublicKeyInfo(getBase64EncodedPublicKey(keyPair));
        secretKey     = createSharedSecret(keyPair.getPrivate(), publicKeyInfo.getPublicKey());
        iv            = new IvParameterSpec(decryptBytes(secretKey, publicKeyInfo.getIv()));
    }

    public @Override String toString() {
        StringBuilder sb = new StringBuilder();
        String        f1 = props.getProperty("to.str.fmt1");
        String        f2 = props.getProperty("to.str.fmt2");

        sb.append(String.format(f1, msgs.getString("msg.label.provider"), props.getProperty("crypto.bouncy-castle.provider"))).append("; ");
        sb.append(String.format(f1, msgs.getString("msg.label.public_key_info"), publicKeyInfo)).append("; ");
        sb.append(String.format(f2, msgs.getString("msg.label.iv_length"), props.getInt("crypto.iv.length"))).append("; ");
        sb.append(String.format(f1, msgs.getString("msg.label.aes_algorithm"), props.getProperty("crypto.aes.algorithm"))).append("; ");
        sb.append(String.format(f2, msgs.getString("msg.label.aes_key_length"), props.getInt("crypto.aes.key_length"))).append("; ");
        sb.append(String.format(f1, msgs.getString("msg.label.aes_transform"), props.getProperty("crypto.aes.transformation.with_iv"))).append("; ");
        sb.append(String.format(f1, msgs.getString("msg.label.aes_transform_no_iv"), props.getProperty("crypto.aes.transformation.no_iv"))).append("; ");
        sb.append(String.format(f1, msgs.getString("msg.label.diffie_hellman_algorithm"), props.getProperty("crypto.diffie_hellman.algorithm"))).append("; ");
        sb.append(String.format(f2, msgs.getString("msg.label.diffie_hellman_key_length"), props.getInt("crypto.diffie_hellman.key_length"))).append(';');

        return sb.toString();
    }

    public IvParameterSpec getIv() {
        return iv;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public PublicKeyInfo getPublicKeyInfo() {
        return publicKeyInfo;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public static @NotNull Provider getProvider() {
        return Security.getProvider(props.getProperty("crypto.bouncy-castle.provider"));
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
        return new SecretKeySpec(digest, props.getProperty("crypto.aes.algorithm"));
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
        KeyFactory keyFactory = KeyFactory.getInstance(props.getProperty("crypto.diffie_hellman.algorithm"), props.getProperty("crypto.bouncy-castle.provider"));
        return createSharedSecretDigest(privateKey, keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes)));
    }

    public static byte @NotNull [] createSharedSecretDigest(@NotNull PrivateKey privateKey, @NotNull PublicKey publicKey) throws GeneralSecurityException {
        KeyAgreement keyAgree = getKeyAgreement(privateKey);
        keyAgree.doPhase(publicKey, true);
        return createSHA256Digest(keyAgree.generateSecret());
    }

    public static byte @NotNull [] decryptBytes(@NotNull SecretKey secretKey, byte @NotNull [] cipherTextData) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(props.getProperty("crypto.aes.transformation.no_iv"));
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
        Cipher c = Cipher.getInstance(props.getProperty("crypto.aes.transformation.with_iv"));
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
        Cipher c = Cipher.getInstance(props.getProperty("crypto.aes.transformation.with_iv"));
        c.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return Base64.getEncoder().encodeToString(c.doFinal(plainTextData));
    }

    public static @NotNull String encryptData(@NotNull SecretKey secretKey, @NotNull String plainText) throws GeneralSecurityException {
        return encryptData(secretKey, plainText.getBytes(StandardCharsets.UTF_8));
    }

    public static @NotNull String encryptData(@NotNull SecretKey secretKey, byte @NotNull [] plainTextData) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(props.getProperty("crypto.aes.transformation.no_iv"));
        c.init(Cipher.ENCRYPT_MODE, secretKey);
        return Base64.getEncoder().encodeToString(c.doFinal(plainTextData));
    }

    public static @NotNull IvParameterSpec generateIv() {
        return new IvParameterSpec(getRandom(props.getInt("crypto.iv.length")));
    }

    public static @NotNull KeyPair generateKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(props.getProperty("crypto.diffie_hellman.algorithm"), props.getProperty("crypto.bouncy-castle.provider"));
        keyGen.initialize(props.getInt("crypto.diffie_hellman.key_length"));
        return keyGen.genKeyPair();
    }

    public static @NotNull SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(props.getProperty("crypto.aes.algorithm"));
        keyGenerator.init(props.getInt("crypto.aes.key_length"));
        return keyGenerator.generateKey();
    }

    public static @NotNull String getBase64EncodedPublicKey(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    public static @NotNull String getBase64EncodedSecretKey(SecretKey secretKey) {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static @NotNull KeyAgreement getKeyAgreement(@NotNull PrivateKey privateKey) throws GeneralSecurityException {
        KeyAgreement keyAgree = KeyAgreement.getInstance(props.getProperty("crypto.diffie_hellman.algorithm"), props.getProperty("crypto.bouncy-castle.provider"));
        keyAgree.init(privateKey);
        return keyAgree;
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
