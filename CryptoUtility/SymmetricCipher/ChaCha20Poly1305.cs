namespace CryptoUtility;

/// <inheritdoc cref="ChaCha20Poly1305Impl"/>
public static class ChaCha20Poly1305
{
    private static readonly SymmetricCipher s_Cipher = new ChaCha20Poly1305Impl();

    /// <inheritdoc cref="SymmetricCipher.Cipher"/>
    public static CipherID Cipher => s_Cipher.Cipher;

    /// <inheritdoc cref="SymmetricCipher.KeySizeBytes"/>
    public static int KeySizeBytes => s_Cipher.KeySizeBytes;

    /// <inheritdoc cref="SymmetricCipher.Encrypt(byte[], byte[])"/>
    public static (bool success, byte[] encrypted) Encrypt(byte[] key, byte[] plaintext) =>
        s_Cipher.Encrypt(key, plaintext);

    /// <inheritdoc cref="SymmetricCipher.Decrypt(byte[], byte[])"/>
    public static (bool success, byte[] plaintext) Decrypt(byte[] key, byte[] encrypted) =>
        s_Cipher.Decrypt(key, encrypted);

    /// <inheritdoc cref="SymmetricCipher.EncryptBase64(string, string)"/>
    public static (bool success, string encrypted) Encrypt(string key, string plaintext) =>
        s_Cipher.EncryptBase64(key, plaintext);

    /// <inheritdoc cref="SymmetricCipher.DecryptBase64(string, string)"/>
    public static (bool success, string plaintext) Decrypt(string key, string encrypted) =>
        s_Cipher.DecryptBase64(key, encrypted);

    /// <inheritdoc cref="SymmetricCipher.GenerateKey()"/>
    public static byte[] GenerateKey() => s_Cipher.GenerateKey();

    /// <inheritdoc cref="SymmetricCipher.GenerateKeyBase64()"/>
    public static string GenerateKeyBase64() => s_Cipher.GenerateKeyBase64();
}
