using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

public static class SymmetricCipherExtensions
{
    public static byte[] Encrypt(this ISymmetricCipher cipher, byte[] key, byte[] plaintext)
    {
        byte[] nonce = Array.Empty<byte>();
        byte[] encrypted = Array.Empty<byte>();

        try
        {
            nonce = cipher.GenerateNonce();

            encrypted = cipher.Encrypt(key, plaintext, nonce);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }

        return encrypted;
    }

    public static string EncryptBase64(
        this ISymmetricCipher cipher,
        string keyBase64,
        string plaintextUtf8
    )
    {
        byte[] keyBytes = Array.Empty<byte>();
        byte[] plaintextBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        string encryptedBase64 = string.Empty;

        try
        {
            keyBytes = Convert.FromBase64String(keyBase64);
            plaintextBytes = Encoding.UTF8.GetBytes(plaintextUtf8);
            encryptedBytes = cipher.Encrypt(keyBytes, plaintextBytes);

            encryptedBase64 = Convert.ToBase64String(encryptedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
            CryptographicOperations.ZeroMemory(plaintextBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
        }

        return encryptedBase64;
    }

    public static string DecryptBase64(
        this ISymmetricCipher cipher,
        string keyBase64,
        string encryptedBase64
    )
    {
        byte[] keyBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        byte[] plaintextBytes = Array.Empty<byte>();
        string plaintextUtf8 = string.Empty;

        try
        {
            keyBytes = Convert.FromBase64String(keyBase64);
            encryptedBytes = Convert.FromBase64String(encryptedBase64);
            plaintextBytes = cipher.Decrypt(keyBytes, encryptedBytes);

            plaintextUtf8 = Encoding.UTF8.GetString(plaintextBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }

        return plaintextUtf8;
    }

    public static byte[] Encrypt(this ISymmetricCipher cipher, string keyBase64, byte[] plaintext)
    {
        byte[] keyBytes = Array.Empty<byte>();
        byte[] encrypted = Array.Empty<byte>();

        try
        {
            keyBytes = Convert.FromBase64String(keyBase64);

            encrypted = cipher.Encrypt(keyBytes, plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }

        return encrypted;
    }

    public static byte[] Decrypt(this ISymmetricCipher cipher, string keyBase64, byte[] encrypted)
    {
        byte[] keyBytes = Array.Empty<byte>();
        byte[] plaintext = Array.Empty<byte>();

        try
        {
            keyBytes = Convert.FromBase64String(keyBase64);

            plaintext = cipher.Decrypt(keyBytes, encrypted);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }

        return plaintext;
    }

    public static string EncryptBase64(
        this ISymmetricCipher cipher,
        byte[] key,
        string plaintextUtf8
    )
    {
        byte[] plaintextBytes = Array.Empty<byte>();
        byte[] encryptedBytes = Array.Empty<byte>();
        string encryptedBase64 = string.Empty;

        try
        {
            plaintextBytes = Encoding.UTF8.GetBytes(plaintextUtf8);
            encryptedBytes = cipher.Encrypt(key, plaintextBytes);

            encryptedBase64 = Convert.ToBase64String(encryptedBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintextBytes);
            CryptographicOperations.ZeroMemory(encryptedBytes);
        }

        return encryptedBase64;
    }

    public static string DecryptBase64(
        this ISymmetricCipher cipher,
        byte[] key,
        string encryptedBase64
    )
    {
        byte[] encryptedBytes = Array.Empty<byte>();
        byte[] plaintextBytes = Array.Empty<byte>();
        string plaintextUtf8 = string.Empty;

        try
        {
            encryptedBytes = Convert.FromBase64String(encryptedBase64);
            plaintextBytes = cipher.Decrypt(key, encryptedBytes);

            plaintextUtf8 = Encoding.UTF8.GetString(plaintextBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(encryptedBytes);
            CryptographicOperations.ZeroMemory(plaintextBytes);
        }

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
        if (cipher == null) throw new ArgumentNullException(nameof(cipher));
        return CryptoHelper.GetBytes(cipher.KeySizeBytes);
    }

    public static string GenerateKeyBase64(this ISymmetricCipher cipher)
    {
        if (cipher == null) throw new ArgumentNullException(nameof(cipher));
        byte[] key = Array.Empty<byte>();
        string result = string.Empty;

        try
        {
            key = cipher.GenerateKey();

            result = Convert.ToBase64String(key);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }

        return result;
    }

    public static byte[] GenerateNonce(this ISymmetricCipher cipher)
    {
        if (cipher == null) throw new ArgumentNullException(nameof(cipher));
        return CryptoHelper.GetBytes(cipher.NonceSizeBytes);
    }

    public static string GenerateNonceBase64(this ISymmetricCipher cipher)
    {
        if (cipher == null) throw new ArgumentNullException(nameof(cipher));
        byte[] nonce = Array.Empty<byte>();
        string nonceBase64 = string.Empty;

        try
        {
            nonce = cipher.GenerateNonce();

            nonceBase64 = Convert.ToBase64String(nonce);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(nonce);
        }

        return nonceBase64;
    }
}
