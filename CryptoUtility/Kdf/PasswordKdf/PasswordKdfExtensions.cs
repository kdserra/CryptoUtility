namespace CryptoUtility;

public static class PasswordKdfExtensions
{
    public static string DeriveKeyBase64(
        this IPasswordKdf kdf,
        string password,
        byte[] salt,
        int iterations,
        int outputLength
    )
    {
        byte[] passwordBytes = Convert.FromBase64String(password);
        byte[] keyBytes = kdf.DeriveKey(password, salt, iterations, outputLength);
        string keyBase64 = Convert.ToBase64String(keyBytes);
        return keyBase64;
    }
}
