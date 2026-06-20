namespace CryptoUtility;

public static class PasswordKdfExtensions
{
    public static string DeriveKeyBase64(
        this IPasswordKdf kdf,
        string password,
        int iterations,
        int outputLength,
        byte[] salt
    )
    {
        byte[] keyBytes = kdf.DeriveKey(password, salt, iterations, outputLength);
        string keyBase64 = Convert.ToBase64String(keyBytes);
        return keyBase64;
    }
}
