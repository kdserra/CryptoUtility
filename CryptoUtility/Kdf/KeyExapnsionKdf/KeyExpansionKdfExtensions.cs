namespace CryptoUtility;

/// <summary>
/// Provides extension methods for Key Expansion KDFs (such as HKDF).
/// </summary>
public static class KeyExpansionKdfExtensions
{
    /// <summary>
    /// Derives a key using key expansion KDF from Base64 input parameters, returning the result as a Base64-encoded string.
    /// </summary>
    /// <param name="kdf">The key expansion KDF instance.</param>
    /// <param name="inputKeyMaterial">The input key material in Base64 format.</param>
    /// <param name="salt">The salt value in Base64 format.</param>
    /// <param name="info">The context/application specific information in Base64 format.</param>
    /// <param name="iterations">The number of iterations to perform.</param>
    /// <param name="outputLength">The desired length of the derived key in bytes.</param>
    /// <returns>A Base64-encoded string representing the derived key, or an empty string if derivation fails.</returns>
    public static string DeriveKeyBase64(
        this IKeyExpansionKdf kdf,
        string inputKeyMaterial,
        string salt,
        string info,
        int iterations,
        int outputLength
    )
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(kdf, inputKeyMaterial, salt, info))
            {
                return string.Empty;
            }

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
            return keyBase64;
        }
        catch
        {
            return string.Empty;
        }
    }
}
