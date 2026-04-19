namespace CryptoUtility;

/// <inheritdoc cref="Aes256GcmImpl"/>
public static class Aes256Gcm
{
    private static readonly SymmetricCipherAEAD s_Cipher = new Aes256GcmImpl();

    /// <inheritdoc cref="SymmetricCipher.CipherID"/>
    public static readonly CipherID Cipher = s_Cipher.CipherID;

    /// <inheritdoc cref="SymmetricCipher.KeySizeBytes"/>
    public static int KeySizeBytes = s_Cipher.KeySizeBytes;

    /// <inheritdoc cref="SymmetricCipher.Encrypt"/>
    public static (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext) =>
        s_Cipher.Encrypt(key, plaintext);

    /// <inheritdoc cref="SymmetricCipher.Decrypt"/>
    public static (bool success, byte[] plaintext) Decrypt(byte[] key, byte[] encrypted) =>
        s_Cipher.Decrypt(key, encrypted);

    /// <inheritdoc cref="SymmetricCipherAE.Encrypt"/>
    public static (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce
    ) => s_Cipher.Encrypt(key, plaintext, nonce);

    /// <inheritdoc cref="SymmetricCipherAEAD.Encrypt"/>
    public static (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    ) => s_Cipher.Encrypt(key, plaintext, nonce, aad);

    /// <inheritdoc cref="SymmetricCipher.EncryptBase64(string, string)"/>
    public static (bool success, string encrypted) EncryptBase64(string key, string plaintext) =>
        s_Cipher.EncryptBase64(key, plaintext);

    /// <inheritdoc cref="SymmetricCipher.DecryptBase64(string, string)"/>
    public static (bool success, string plaintext) DecryptBase64(string key, string encrypted) =>
        s_Cipher.DecryptBase64(key, encrypted);

    /// <inheritdoc cref="SymmetricCipher.GenerateKey"/>
    public static byte[] GenerateKey() => s_Cipher.GenerateKey();

    /// <inheritdoc cref="SymmetricCipher.GenerateKeyBase64"/>
    public static string GenerateKeyBase64() => s_Cipher.GenerateKeyBase64();
}
