using System.Security.Cryptography;

namespace CryptoUtility;

public static class PasswordKdfExtensions
{
    public static string DeriveKeyBase64(
        this IPasswordKdf kdf,
        string passwordUtf8,
        string saltBase64,
        int iterations,
        int outputLength
    )
    {
        byte[] saltBytes = Array.Empty<byte>();
        byte[] keyBytes = Array.Empty<byte>();
        string keyBase64 = string.Empty;

        try
        {
            saltBytes = Convert.FromBase64String(saltBase64);
            keyBytes = kdf.DeriveKey(passwordUtf8, saltBytes, iterations, outputLength);

            keyBase64 = Convert.ToBase64String(keyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(saltBytes);
            CryptographicOperations.ZeroMemory(keyBytes);
        }

        return keyBase64;
    }

    public static bool TryDeriveKey(
        this IPasswordKdf kdf,
        string passwordUtf8,
        byte[] salt,
        int iterations,
        int outputLength,
        out byte[] derivedKey
    )
    {
        try
        {
            derivedKey = kdf.DeriveKey(passwordUtf8, salt, iterations, outputLength);

            return true;
        }
        catch
        {
            derivedKey = Array.Empty<byte>();

            return false;
        }
    }

    public static bool TryDeriveKeyBase64(
        this IPasswordKdf kdf,
        string passwordUtf8,
        string saltBase64,
        int iterations,
        int outputLength,
        out string derivedKeyBase64
    )
    {
        try
        {
            derivedKeyBase64 = kdf.DeriveKeyBase64(
                passwordUtf8,
                saltBase64,
                iterations,
                outputLength
            );

            return true;
        }
        catch
        {
            derivedKeyBase64 = string.Empty;

            return false;
        }
    }
}
