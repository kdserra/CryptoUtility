namespace CryptoUtility;

public static class KeyExpansionKdfExtensions
{
    public static string DeriveKeyBase64(
        this IKeyExpansionKdf kdf,
        string inputKeyMaterial,
        string salt,
        string info,
        int iterations,
        int outputLength
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
        return keyBase64;
    }
}
