using System.Security.Cryptography;

namespace CryptoUtility;

public static class KeyExpansionKdfExtensions
{
    public static string DeriveKeyBase64(
        this IKeyExpansionKdf kdf,
        string inputKeyMaterial,
        int iterations,
        int outputLength,
        string salt,
        string info
    )
    {
        byte[] inputKeyMaterialBytes = Convert.FromBase64String(inputKeyMaterial);
        byte[] saltBytes = Convert.FromBase64String(salt);
        byte[] infoBytes = Convert.FromBase64String(info);

        byte[] keyBytes = kdf.DeriveKey(
            inputKeyMaterialBytes,
            iterations,
            outputLength,
            saltBytes,
            infoBytes
        );

        string keyBase64 = Convert.ToBase64String(keyBytes);

        CryptographicOperations.ZeroMemory(inputKeyMaterialBytes);
        CryptographicOperations.ZeroMemory(saltBytes);
        CryptographicOperations.ZeroMemory(infoBytes);
        CryptographicOperations.ZeroMemory(keyBytes);

        return keyBase64;
    }

    public static string DeriveKeyBase64(
        this IKeyExpansionKdf kdf,
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info
    )
    {
        byte[] keyBytes = kdf.DeriveKey(inputKeyMaterial, iterations, outputLength, salt, info);
        string keyBase64 = Convert.ToBase64String(keyBytes);

        CryptographicOperations.ZeroMemory(keyBytes);

        return keyBase64;
    }

    public static bool TryDeriveKey(
        this IKeyExpansionKdf kdf,
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info,
        out byte[] derivedKey
    )
    {
        try
        {
            derivedKey = kdf.DeriveKey(inputKeyMaterial, iterations, outputLength, salt, info);

            return true;
        }
        catch
        {
            derivedKey = Array.Empty<byte>();

            return false;
        }
    }

    public static bool TryDeriveKeyBase64(
        this IKeyExpansionKdf kdf,
        string inputKeyMaterial,
        int iterations,
        int outputLength,
        string salt,
        string info,
        out string derivedKey
    )
    {
        try
        {
            derivedKey = kdf.DeriveKeyBase64(
                inputKeyMaterial,
                iterations,
                outputLength,
                salt,
                info
            );

            return true;
        }
        catch
        {
            derivedKey = string.Empty;

            return false;
        }
    }

    public static bool TryDeriveKeyBase64(
        this IKeyExpansionKdf kdf,
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info,
        out string derivedKey
    )
    {
        try
        {
            derivedKey = kdf.DeriveKeyBase64(
                inputKeyMaterial,
                iterations,
                outputLength,
                salt,
                info
            );

            return true;
        }
        catch
        {
            derivedKey = string.Empty;

            return false;
        }
    }
}
