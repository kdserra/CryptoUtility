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
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(kdf, password, salt))
            {
                return string.Empty;
            }

            byte[] keyBytes = kdf.DeriveKey(password, salt, iterations, outputLength);
            string keyBase64 = Convert.ToBase64String(keyBytes);
            return keyBase64;
        }
        catch
        {
            return string.Empty;
        }
    }
}
