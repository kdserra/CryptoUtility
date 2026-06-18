namespace CryptoUtility;

public static class HashProviderExtensions
{
    /// <summary>
    /// Computes the hash value for the specified input data using the algorithm implemented by the derived class.
    /// </summary>
    /// <param name="hashProvider">The hash provider instance.</param>
    /// <param name="message">The UTF8 string containing the data to hash.</param>
    /// <returns>A base64 string that contains the computed hash value.</returns>
    public static string HashBase64(this IHashProvider hashProvider, string message)
    {
        LibraryHelper.ThrowIfAnyNull(hashProvider, message);

        byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
        byte[] hashBytes = hashProvider.Hash(messageBytes);
        string hashBase64 = Convert.ToBase64String(hashBytes);

        return hashBase64;
    }
}
