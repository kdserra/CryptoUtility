namespace CryptoUtility;

public static class HashProviderExtensions
{
    public static string HashBase64(this IHashProvider hashProvider, string message)
    {
        LibraryHelper.ThrowIfAnyNull(hashProvider, message);

        byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
        byte[] hashBytes = hashProvider.Hash(messageBytes);
        string hashBase64 = Convert.ToBase64String(hashBytes);

        return hashBase64;
    }
}
