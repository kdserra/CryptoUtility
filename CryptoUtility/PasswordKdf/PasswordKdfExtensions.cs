using System.Security.Cryptography;

namespace CryptoUtility;

public static class PasswordKdfExtensions
{
    public static string DeriveKeyBase64(
        this IPasswordKdf kdf,
        string password,
        string salt,
        int iterations,
        int outputLength
    )
    {
        byte[] saltBytes = Convert.FromBase64String(salt);
        byte[] keyBytes = kdf.DeriveKey(password, saltBytes, iterations, outputLength);
        string keyBase64 = Convert.ToBase64String(keyBytes);

        CryptographicOperations.ZeroMemory(keyBytes);

        return keyBase64;
    }

    public static bool TryDeriveKey(
        this IPasswordKdf kdf,
        string password,
        byte[] salt,
        int iterations,
        int outputLength,
        out byte[] derivedKey
    )
    {
        try
        {
            derivedKey = kdf.DeriveKey(password, salt, iterations, outputLength);
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
        string password,
        string salt,
        int iterations,
        int outputLength,
        out string derivedKey
    )
    {
        try
        {
            derivedKey = kdf.DeriveKeyBase64(password, salt, iterations, outputLength);
            return true;
        }
        catch
        {
            derivedKey = string.Empty;
            return false;
        }
    }
}
