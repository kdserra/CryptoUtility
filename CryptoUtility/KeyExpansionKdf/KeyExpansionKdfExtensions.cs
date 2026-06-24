using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Provides extension methods for the <see cref="IKeyExpansionKdf"/> interface.
/// </summary>
public static class KeyExpansionKdfExtensions
{
    /// <summary>
    /// Derives a key as a Base64-encoded string using Base64-encoded inputs.
    /// </summary>
    public static string DeriveKeyBase64(
        this IKeyExpansionKdf kdf,
        string inputKeyMaterialBase64,
        int outputLength,
        string saltBase64,
        string infoBase64
    )
    {
        LibraryHelper.ThrowIfAnyNull(kdf, inputKeyMaterialBase64, saltBase64, infoBase64);

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

    /// <summary>
    /// Derives a key as a Base64-encoded string using byte array inputs.
    /// </summary>
    public static string DeriveKeyBase64(
        this IKeyExpansionKdf kdf,
        byte[] inputKeyMaterial,
        int outputLength,
        byte[] salt,
        byte[] info
    )
    {
        LibraryHelper.ThrowIfAnyNull(kdf, inputKeyMaterial, salt, info);

        byte[] keyBytes = Array.Empty<byte>();
        string keyBase64 = string.Empty;

        try
        {
            keyBytes = kdf.DeriveKey(inputKeyMaterial, outputLength, salt, info);

            keyBase64 = Convert.ToBase64String(keyBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyBytes);
        }

        return keyBase64;
    }

    /// <summary>
    /// Attempts to derive a key, returning a boolean indicating success.
    /// </summary>
    public static bool TryDeriveKey(
        this IKeyExpansionKdf kdf,
        byte[] inputKeyMaterial,
        int outputLength,
        byte[] salt,
        byte[] info,
        out byte[] derivedKey
    )
    {
        try
        {
            derivedKey = kdf.DeriveKey(inputKeyMaterial, outputLength, salt, info);

            return true;
        }
        catch
        {
            derivedKey = Array.Empty<byte>();

            return false;
        }
    }

    /// <summary>
    /// Attempts to derive a key as a Base64-encoded string using Base64-encoded inputs.
    /// </summary>
    public static bool TryDeriveKeyBase64(
        this IKeyExpansionKdf kdf,
        string inputKeyMaterialBase64,
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

    /// <summary>
    /// Attempts to derive a key as a Base64-encoded string using byte array inputs.
    /// </summary>
    public static bool TryDeriveKeyBase64(
        this IKeyExpansionKdf kdf,
        byte[] inputKeyMaterial,
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
