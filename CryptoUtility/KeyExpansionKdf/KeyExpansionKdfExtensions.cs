using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// Provides extension methods for Key Expansion KDFs (such as HKDF).
/// </summary>
public static class KeyExpansionKdfExtensions
{
    /// <summary>
    /// Derives a key using key expansion KDF, returning the result as a Base64-encoded string.
    /// </summary>
    /// <param name="kdf">The key expansion KDF instance.</param>
    /// <param name="inputKeyMaterial">The input key material.</param>
    /// <param name="salt">The salt value.</param>
    /// <param name="info">The context/application specific information.</param>
    /// <param name="iterations">The number of iterations to perform.</param>
    /// <param name="outputLength">The desired length of the derived key in bytes.</param>
    /// <returns>A Base64-encoded string representing the derived key, or an empty string if derivation fails.</returns>
    public static string DeriveKeyBase64(
        this IKeyExpansionKdf kdf,
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info
    )
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(kdf, inputKeyMaterial, salt, info))
            {
                return string.Empty;
            }

            byte[] keyBytes = kdf.DeriveKey(inputKeyMaterial, iterations, outputLength, salt, info);
            string keyBase64 = Convert.ToBase64String(keyBytes);

            CryptographicOperations.ZeroMemory(keyBytes);

            return keyBase64;
        }
        catch
        {
            return string.Empty;
        }
    }
}
