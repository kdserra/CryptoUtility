using System.Text;

namespace CryptoUtility;

public static class HashProviderExtensions
{
    public static string HashBase64(this IHashProvider hashProvider, string message)
    {
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] hashBytes = hashProvider.Hash(messageBytes);
        string hashBase64 = Convert.ToBase64String(hashBytes);

        return hashBase64;
    }

    public static bool TryHash(this IHashProvider hashProvider, byte[] message, out byte[] hash)
    {
        try
        {
            hash = hashProvider.Hash(message);
            return true;
        }
        catch
        {
            hash = Array.Empty<byte>();
            return false;
        }
    }

    public static bool TryHashBase64(
        this IHashProvider hashProvider,
        string message,
        out string hash
    )
    {
        try
        {
            hash = hashProvider.HashBase64(message);
            return true;
        }
        catch
        {
            hash = string.Empty;
            return false;
        }
    }
}
