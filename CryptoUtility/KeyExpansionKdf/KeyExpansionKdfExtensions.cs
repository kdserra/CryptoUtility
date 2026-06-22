using System.Security.Cryptography;

namespace CryptoUtility;

public static class KeyExpansionKdfExtensions
{
    public static string DeriveKeyBase64(
        this IKeyExpansionKdf kdf,
        string inputKeyMaterialBase64,
        int iterations,
        int outputLength,
        string saltBase64,
        string infoBase64
    )
    {
        byte[] inputKeyMaterialBytes = Array.Empty<byte>();
        byte[] saltBytes = Array.Empty<byte>();
        byte[] infoBytes = Array.Empty<byte>();
        byte[] keyBytes = Array.Empty<byte>();
        string keyBase64 = string.Empty;

        try
        {
            inputKeyMaterialBytes = Convert.FromBase64String(inputKeyMaterialBase64);
            saltBytes = Convert.FromBase64String(saltBase64);
            infoBytes = Convert.FromBase64String(infoBase64);

            keyBytes = kdf.DeriveKey(
                inputKeyMaterialBytes,
                iterations,
                outputLength,
                saltBytes,
                infoBytes
            );

            keyBase64 = Convert.ToBase64String(keyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(inputKeyMaterialBytes);
            CryptographicOperations.ZeroMemory(saltBytes);
            CryptographicOperations.ZeroMemory(infoBytes);
            CryptographicOperations.ZeroMemory(keyBytes);
        }

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
        byte[] keyBytes = Array.Empty<byte>();
        string keyBase64 = string.Empty;

        try
        {
            keyBytes = kdf.DeriveKey(inputKeyMaterial, iterations, outputLength, salt, info);

            keyBase64 = Convert.ToBase64String(keyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }

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
        string inputKeyMaterialBase64,
        int iterations,
        int outputLength,
        string saltBase64,
        string infoBase64,
        out string derivedKeyBase64
    )
    {
        try
        {
            derivedKeyBase64 = kdf.DeriveKeyBase64(
                inputKeyMaterialBase64,
                iterations,
                outputLength,
                saltBase64,
                infoBase64
            );

            return true;
        }
        catch
        {
            derivedKeyBase64 = string.Empty;

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
        out string derivedKeyBase64
    )
    {
        try
        {
            derivedKeyBase64 = kdf.DeriveKeyBase64(
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
            derivedKeyBase64 = string.Empty;

            return false;
        }
    }
}
