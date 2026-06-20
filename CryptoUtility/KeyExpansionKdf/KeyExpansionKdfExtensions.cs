using System.Security.Cryptography;

namespace CryptoUtility;

public static class KeyExpansionKdfExtensions
{
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
