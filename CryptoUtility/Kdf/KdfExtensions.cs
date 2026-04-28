namespace CryptoUtility;

public static class KdfExtensions
{
    public static string DeriveKeyBase64(
        this IKdf kdf,
        string inputKeyMaterial,
        string salt,
        int iterations,
        int outputLength
    )
    {
        byte[] inputKeyMaterialBytes = Convert.FromBase64String(inputKeyMaterial);
        byte[] saltBytes = Convert.FromBase64String(salt);
        byte[] keyBytes = kdf.DeriveKey(inputKeyMaterialBytes, saltBytes, iterations, outputLength);
        string keyBase64 = Convert.ToBase64String(keyBytes);
        return keyBase64;
    }

    public static string DeriveKeyBase64(
        this IKdf kdf,
        byte[] inputKeyMaterial,
        byte[] salt,
        int iterations,
        int outputLength
    )
    {
        byte[] keyBytes = kdf.DeriveKey(inputKeyMaterial, salt, iterations, outputLength);
        string keyBase64 = Convert.ToBase64String(keyBytes);
        return keyBase64;
    }
}
