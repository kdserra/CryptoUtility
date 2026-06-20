using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

public static class SymmetricCipherExtensions
{
    public static byte[] Encrypt(this ISymmetricCipher cipher, byte[] key, byte[] plaintext)
    {
        return cipher.Encrypt(key, plaintext, nonce: cipher.GenerateNonce());
    }

    public static byte[] Encrypt(
        this ISymmetricCipher cipher,
        string keyBase64,
        string plaintextUtf8,
        string nonceBase64
    )
    {
        byte[] key = Convert.FromBase64String(keyBase64);
        byte[] plaintext = Encoding.UTF8.GetBytes(plaintextUtf8);
        byte[] nonce = Convert.FromBase64String(nonceBase64);

        byte[] encrypted = cipher.Encrypt(key, plaintext, nonce);

        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(plaintext);
        CryptographicOperations.ZeroMemory(nonce);

        return encrypted;
    }

    public static byte[] Encrypt(
        this ISymmetricCipherAEAD cipher,
        string keyBase64,
        string plaintextUtf8,
        string nonceBase64,
        string aadBase64
    )
    {
        byte[] key = Convert.FromBase64String(keyBase64);
        byte[] plaintext = Encoding.UTF8.GetBytes(plaintextUtf8);
        byte[] nonce = Convert.FromBase64String(nonceBase64);
        byte[] aad = Convert.FromBase64String(aadBase64);

        byte[] encrypted = cipher.Encrypt(key, plaintext, nonce, aad);

        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(plaintext);
        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(aad);

        return encrypted;
    }

    public static string EncryptBase64(
        this ISymmetricCipher cipher,
        string keyBase64,
        string plaintextUtf8,
        string nonceBase64
    )
    {
        byte[] key = Convert.FromBase64String(keyBase64);
        byte[] plaintext = Encoding.UTF8.GetBytes(plaintextUtf8);
        byte[] nonce = Convert.FromBase64String(nonceBase64);

        byte[] encrypted = cipher.Encrypt(key, plaintext, nonce);
        string encryptedBase64 = Convert.ToBase64String(encrypted);

        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(plaintext);
        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(encrypted);

        return encryptedBase64;
    }

    public static string EncryptBase64(
        this ISymmetricCipherAEAD cipher,
        string keyBase64,
        string plaintextUtf8,
        string nonceBase64,
        string aadBase64
    )
    {
        byte[] key = Convert.FromBase64String(keyBase64);
        byte[] plaintext = Encoding.UTF8.GetBytes(plaintextUtf8);
        byte[] nonce = Convert.FromBase64String(nonceBase64);
        byte[] aad = Convert.FromBase64String(aadBase64);

        byte[] encrypted = cipher.Encrypt(key, plaintext, nonce, aad);
        string encryptedBase64 = Convert.ToBase64String(encrypted);

        CryptographicOperations.ZeroMemory(key);
        CryptographicOperations.ZeroMemory(plaintext);
        CryptographicOperations.ZeroMemory(nonce);
        CryptographicOperations.ZeroMemory(aad);
        CryptographicOperations.ZeroMemory(encrypted);

        return encryptedBase64;
    }

    public static string EncryptBase64(
        this ISymmetricCipher cipher,
        string keyBase64,
        string plaintextUtf8
    )
    {
        byte[] keyBytes = Convert.FromBase64String(keyBase64);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintextUtf8);
        byte[] encryptedBytes = cipher.Encrypt(keyBytes, plaintextBytes);
        string encryptedBase64 = Convert.ToBase64String(encryptedBytes);

        CryptographicOperations.ZeroMemory(keyBytes);
        CryptographicOperations.ZeroMemory(plaintextBytes);
        CryptographicOperations.ZeroMemory(encryptedBytes);

        return encryptedBase64;
    }

    public static string DecryptBase64(
        this ISymmetricCipher cipher,
        string keyBase64,
        string encryptedBase64
    )
    {
        byte[] keyBytes = Convert.FromBase64String(keyBase64);
        byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);
        byte[] plaintextBytes = cipher.Decrypt(keyBytes, encryptedBytes);
        string plaintextUtf8 = Encoding.UTF8.GetString(plaintextBytes);

        CryptographicOperations.ZeroMemory(keyBytes);
        CryptographicOperations.ZeroMemory(plaintextBytes);
        CryptographicOperations.ZeroMemory(plaintextBytes);

        return plaintextUtf8;
    }

    public static byte[] Encrypt(this ISymmetricCipher cipher, string keyBase64, byte[] plaintext)
    {
        byte[] keyBytes = Convert.FromBase64String(keyBase64);
        byte[] encrypted = cipher.Encrypt(keyBytes, plaintext);

        CryptographicOperations.ZeroMemory(keyBytes);

        return encrypted;
    }

    public static byte[] Decrypt(this ISymmetricCipher cipher, string keyBase64, byte[] encrypted)
    {
        byte[] keyBytes = Convert.FromBase64String(keyBase64);
        byte[] plaintext = cipher.Decrypt(keyBytes, encrypted);

        CryptographicOperations.ZeroMemory(keyBytes);

        return plaintext;
    }

    public static byte[] Encrypt(this ISymmetricCipher cipher, byte[] key, string plaintextUtf8)
    {
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintextUtf8);
        byte[] encrypted = cipher.Encrypt(key, plaintextBytes);

        CryptographicOperations.ZeroMemory(plaintextBytes);

        return encrypted;
    }

    public static byte[] Decrypt(this ISymmetricCipher cipher, byte[] key, string encryptedBase64)
    {
        byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);
        byte[] plaintext = cipher.Decrypt(key, encryptedBytes);

        CryptographicOperations.ZeroMemory(encryptedBytes);

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

        CryptographicOperations.ZeroMemory(key);

        return result;
    }

    public static bool TryEncrypt(
        this ISymmetricCipher cipher,
        byte[] key,
        byte[] plaintext,
        out byte[] encrypted
    )
    {
        try
        {
            encrypted = cipher.Encrypt(key, plaintext);

            return false;
        }
        catch
        {
            encrypted = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryDecrypt(
        this ISymmetricCipher cipher,
        byte[] key,
        byte[] encrypted,
        out byte[] plaintext
    )
    {
        try
        {
            plaintext = cipher.Decrypt(key, encrypted);

            return false;
        }
        catch
        {
            plaintext = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryEncrypt(
        this ISymmetricCipher cipher,
        string keyBase64,
        byte[] plaintext,
        out byte[] encrypted
    )
    {
        try
        {
            encrypted = cipher.Encrypt(keyBase64, plaintext);

            return false;
        }
        catch
        {
            encrypted = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryDecrypt(
        this ISymmetricCipher cipher,
        string keyBase64,
        byte[] encrypted,
        out byte[] plaintext
    )
    {
        try
        {
            plaintext = cipher.Encrypt(keyBase64, encrypted);

            return false;
        }
        catch
        {
            plaintext = Array.Empty<byte>();

            return false;
        }
    }

    public static bool TryEncrypt(
        this ISymmetricCipher cipher,
        byte[] key,
        string plaintextBase64,
        out byte[] encrypted
    )
    {
        try
        {
            encrypted = cipher.Encrypt(key, plaintextBase64);

            return false;
        }
        catch
        {
            encrypted = Array.Empty<byte>();

            return false;
        }
    }

    public static bool TryDecrypt(
        this ISymmetricCipher cipher,
        byte[] key,
        string encryptedBase64,
        out byte[] plaintext
    )
    {
        try
        {
            plaintext = cipher.Decrypt(key, encryptedBase64);

            return false;
        }
        catch
        {
            plaintext = Array.Empty<byte>();

            return false;
        }
    }
}
