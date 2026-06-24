using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Provides extension methods for the <see cref="IPasswordKdf"/> interface.
/// </summary>
public static class PasswordKdfExtensions
{
    /// <summary>
    /// Derives a key as a Base64-encoded string using a Base64-encoded salt.
    /// </summary>
    public static string DeriveKeyBase64(
        this IPasswordKdf kdf,
        string passwordUtf8,
        string saltBase64,
        int outputLength
    )
    {
        byte[] saltBytes = Array.Empty<byte>();
        byte[] keyBytes = Array.Empty<byte>();
        string keyBase64 = string.Empty;

        try
        {
            saltBytes = Convert.FromBase64String(saltBase64);
            keyBytes = kdf.DeriveKey(passwordUtf8, saltBytes, outputLength);

            keyBase64 = Convert.ToBase64String(keyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(saltBytes);
            CryptographicOperations.ZeroMemory(keyBytes);
        }

        return keyBase64;
    }

    /// <summary>
    /// Attempts to derive a key, returning a boolean indicating success.
    /// </summary>
    public static bool TryDeriveKey(
        this IPasswordKdf kdf,
        string passwordUtf8,
        byte[] salt,
        int outputLength,
        out byte[] derivedKey
    )
    {
        try
        {
            derivedKey = kdf.DeriveKey(passwordUtf8, salt, outputLength);

            return true;
        }
        catch
        {
            derivedKey = Array.Empty<byte>();

            return false;
        }
    }

    /// <summary>
    /// Attempts to derive a key as a Base64-encoded string using a Base64-encoded salt.
    /// </summary>
    public static bool TryDeriveKeyBase64(
        this IPasswordKdf kdf,
        string passwordUtf8,
        string saltBase64,
        int outputLength,
        out string derivedKeyBase64
    )
    {
        try
        {
            derivedKeyBase64 = kdf.DeriveKeyBase64(passwordUtf8, saltBase64, outputLength);

            return true;
        }
        catch
        {
            derivedKeyBase64 = string.Empty;

            return false;
        }
    }
}
