using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;
    /// <summary>
    /// Provides extension methods for simplified symmetric key encryption and decryption.
    /// </summary>

public static class SymmetricCipherExtensions
{
    /// <summary>
    /// Encrypts the specified plaintext data.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="key">The symmetric key.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <returns>A byte array containing the result.</returns>
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
    /// <summary>
    /// Encrypts the specified plaintext data using Base64-encoded strings.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="keyBase64">The Base64-encoded symmetric key.</param>
    /// <param name="plaintextUtf8">The plaintext string to encrypt.</param>
    /// <returns>A string containing the result.</returns>

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
    /// <summary>
    /// Decrypts the specified ciphertext data using Base64-encoded strings.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="keyBase64">The Base64-encoded symmetric key.</param>
    /// <param name="encryptedBase64">The Base64-encoded encrypted ciphertext.</param>
    /// <returns>A string containing the result.</returns>

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
    /// <summary>
    /// Encrypts the specified plaintext data.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="keyBase64">The Base64-encoded symmetric key.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <returns>A byte array containing the result.</returns>

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
    /// <summary>
    /// Decrypts the specified ciphertext data.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="keyBase64">The Base64-encoded symmetric key.</param>
    /// <param name="encrypted">The encrypted ciphertext bytes.</param>
    /// <returns>A byte array containing the result.</returns>

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
    /// <summary>
    /// Encrypts the specified plaintext data using Base64-encoded strings.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="key">The symmetric key.</param>
    /// <param name="plaintextUtf8">The plaintext string to encrypt.</param>
    /// <returns>A string containing the result.</returns>

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
    /// <summary>
    /// Decrypts the specified ciphertext data using Base64-encoded strings.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="key">The symmetric key.</param>
    /// <param name="encryptedBase64">The Base64-encoded encrypted ciphertext.</param>
    /// <returns>A string containing the result.</returns>

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
    /// <summary>
    /// Attempts to encrypts the specified plaintext data.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="key">The symmetric key.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <param name="encrypted">The encrypted ciphertext bytes.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>

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
    /// <summary>
    /// Attempts to decrypts the specified ciphertext data.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="key">The symmetric key.</param>
    /// <param name="encrypted">The encrypted ciphertext bytes.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>

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
    /// <summary>
    /// Attempts to encrypts the specified plaintext data.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="keyBase64">The Base64-encoded symmetric key.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <param name="encrypted">The encrypted ciphertext bytes.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>

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
    /// <summary>
    /// Attempts to decrypts the specified ciphertext data.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="keyBase64">The Base64-encoded symmetric key.</param>
    /// <param name="encrypted">The encrypted ciphertext bytes.</param>
    /// <param name="plaintext">The plaintext bytes to encrypt.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>

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
    /// <summary>
    /// Attempts to encrypts the specified plaintext data using base64-encoded strings.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="keyBase64">The Base64-encoded symmetric key.</param>
    /// <param name="plaintextUtf8">The plaintext string to encrypt.</param>
    /// <param name="encryptedBase64">The Base64-encoded encrypted ciphertext.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>

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
    /// <summary>
    /// Attempts to decrypts the specified ciphertext data using base64-encoded strings.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <param name="keyBase64">The Base64-encoded symmetric key.</param>
    /// <param name="encryptedBase64">The Base64-encoded encrypted ciphertext.</param>
    /// <param name="plaintextUtf8">The plaintext string to encrypt.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>

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
    /// <summary>
    /// Generate key.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <returns>A byte array containing the result.</returns>

    public static byte[] GenerateKey(this ISymmetricCipher cipher)
    {
        LibraryHelper.ThrowIfAnyNull(cipher);
        return CryptoHelper.GetBytes(cipher.KeySizeBytes);
    }
    /// <summary>
    /// Generate key using Base64-encoded strings.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <returns>A string containing the result.</returns>

    public static string GenerateKeyBase64(this ISymmetricCipher cipher)
    {
        LibraryHelper.ThrowIfAnyNull(cipher);
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
    /// <summary>
    /// Generate nonce.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <returns>A byte array containing the result.</returns>

    public static byte[] GenerateNonce(this ISymmetricCipher cipher)
    {
        LibraryHelper.ThrowIfAnyNull(cipher);
        return CryptoHelper.GetBytes(cipher.NonceSizeBytes);
    }
    /// <summary>
    /// Generate nonce using Base64-encoded strings.
    /// </summary>
    /// <param name="cipher">The symmetric cipher instance.</param>
    /// <returns>A string containing the result.</returns>

    public static string GenerateNonceBase64(this ISymmetricCipher cipher)
    {
        LibraryHelper.ThrowIfAnyNull(cipher);
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
