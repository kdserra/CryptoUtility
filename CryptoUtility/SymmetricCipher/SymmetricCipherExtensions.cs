using System.Text;

namespace CryptoUtility;

public static class SymmetricCipherExtensions
{
    public static byte[] Encrypt(this ISymmetricCipher cipher, byte[] key, byte[] plaintext)
    {
        return cipher.Encrypt(key, plaintext, nonce: cipher.GenerateNonce());
    }

    public static string EncryptBase64(this ISymmetricCipher cipher, string key, string plaintext)
    {
        byte[] keyBytes = Convert.FromBase64String(key);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] encryptedBytes = cipher.Encrypt(keyBytes, plaintextBytes);
        string encryptedBase64 = Convert.ToBase64String(encryptedBytes);

        return encryptedBase64;
    }

    public static string DecryptBase64(this ISymmetricCipher cipher, string key, string encrypted)
    {
        byte[] keyBytes = Convert.FromBase64String(key);
        byte[] encryptedBytes = Convert.FromBase64String(encrypted);
        byte[] plaintextBytes = cipher.Decrypt(keyBytes, encryptedBytes);
        string plaintextBase64 = Encoding.UTF8.GetString(plaintextBytes);

        return plaintextBase64;
    }

    public static byte[] Encrypt(this ISymmetricCipher cipher, string keyBase64, byte[] plaintext)
    {
        byte[] keyBytes = Convert.FromBase64String(keyBase64);
        byte[] encrypted = cipher.Encrypt(keyBytes, plaintext);
        return encrypted;
    }

    public static byte[] Decrypt(this ISymmetricCipher cipher, string keyBase64, byte[] encrypted)
    {
        byte[] keyBytes = Convert.FromBase64String(keyBase64);
        byte[] plaintext = cipher.Decrypt(keyBytes, encrypted);
        return plaintext;
    }

    public static byte[] GenerateKey(this ISymmetricCipher cipher)
    {
        return CryptoHelper.GetBytes(cipher.KeySizeBytes);
    }

    public static byte[] GenerateNonce(this ISymmetricCipher cipher)
    {
        return CryptoHelper.GetBytes(cipher.NonceSizeBytes);
    }

    public static string GenerateNonceBase64(this ISymmetricCipher cipher)
    {
        return Convert.ToBase64String(cipher.GenerateNonce());
    }

    public static string GenerateKeyBase64(this ISymmetricCipher cipher)
    {
        byte[] key = cipher.GenerateKey();
        string result = Convert.ToBase64String(key);
        return result;
    }
}
