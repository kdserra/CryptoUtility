using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

public static class HashProviderExtensions
{
    public static string HashBase64(this IHashProvider hashProvider, string messageUtf8)
    {
        byte[] messageBytes = Encoding.UTF8.GetBytes(messageUtf8);
        byte[] hashBytes = hashProvider.Hash(messageBytes);

        string hashBase64 = Convert.ToBase64String(hashBytes);

        CryptographicOperations.ZeroMemory(messageBytes);
        CryptographicOperations.ZeroMemory(hashBytes);

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
        string messageUtf8,
        out string hashBase64
    )
    {
        try
        {
            hashBase64 = hashProvider.HashBase64(messageUtf8);

            return true;
        }
        catch
        {
            hashBase64 = string.Empty;

            return false;
        }
    }
}
