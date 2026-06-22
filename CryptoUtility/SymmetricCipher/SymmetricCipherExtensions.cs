using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

public static class SymmetricCipherExtensions
{
    public static byte[] Encrypt(this ISymmetricCipher cipher, byte[] key, byte[] plaintext)
    {
        byte[] nonce = cipher.GenerateNonce();
        byte[] encrypted = cipher.Encrypt(key, plaintext, nonce);

        CryptographicOperations.ZeroMemory(nonce);

        return encrypted;
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
        CryptographicOperations.ZeroMemory(encryptedBytes);
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

    public static string EncryptBase64(
        this ISymmetricCipher cipher,
        byte[] key,
        string plaintextUtf8
    )
    {
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintextUtf8);
        byte[] encryptedBytes = cipher.Encrypt(key, plaintextBytes);

        string encryptedBase64 = Convert.ToBase64String(encryptedBytes);

        CryptographicOperations.ZeroMemory(plaintextBytes);
        CryptographicOperations.ZeroMemory(encryptedBytes);

        return encryptedBase64;
    }

    public static string DecryptBase64(
        this ISymmetricCipher cipher,
        byte[] key,
        string encryptedBase64
    )
    {
        byte[] encryptedBytes = Convert.FromBase64String(encryptedBase64);
        byte[] plaintextBytes = cipher.Decrypt(key, encryptedBytes);

        string plaintextUtf8 = Encoding.UTF8.GetString(plaintextBytes);

        CryptographicOperations.ZeroMemory(encryptedBytes);
        CryptographicOperations.ZeroMemory(plaintextBytes);

        return plaintextUtf8;
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

            return true;
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

            return true;
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

            return true;
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
            plaintext = cipher.Decrypt(keyBase64, encrypted);

            return true;
        }
        catch
        {
            plaintext = Array.Empty<byte>();

            return false;
        }
    }

    public static bool TryEncryptBase64(
        this ISymmetricCipher cipher,
        string keyBase64,
        string plaintextUtf8,
        out string encryptedBase64
    )
    {
        try
        {
            encryptedBase64 = cipher.EncryptBase64(keyBase64, plaintextUtf8);

            return true;
        }
        catch
        {
            encryptedBase64 = string.Empty;

            return false;
        }
    }

    public static bool TryDecryptBase64(
        this ISymmetricCipher cipher,
        string keyBase64,
        string encryptedBase64,
        out string plaintextUtf8
    )
    {
        try
        {
            plaintextUtf8 = cipher.DecryptBase64(keyBase64, encryptedBase64);

            return true;
        }
        catch
        {
            plaintextUtf8 = string.Empty;

            return false;
        }
    }

    public static byte[] GenerateKey(this ISymmetricCipher cipher)
    {
        return CryptoHelper.GetBytes(cipher.KeySizeBytes);
    }

    public static string GenerateKeyBase64(this ISymmetricCipher cipher)
    {
        byte[] key = cipher.GenerateKey();
        string result = Convert.ToBase64String(key);

        CryptographicOperations.ZeroMemory(key);

        return result;
    }

    public static byte[] GenerateNonce(this ISymmetricCipher cipher)
    {
        return CryptoHelper.GetBytes(cipher.NonceSizeBytes);
    }

    public static string GenerateNonceBase64(this ISymmetricCipher cipher)
    {
        byte[] nonce = cipher.GenerateNonce();

        string nonceBase64 = Convert.ToBase64String(nonce);

        CryptographicOperations.ZeroMemory(nonce);

        return nonceBase64;
    }
}
