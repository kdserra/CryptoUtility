using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

public static class HashProviderExtensions
{
    public static string HashBase64(this IHashProvider hashProvider, string messageUtf8)
    {
        LibraryHelper.ThrowIfAnyNull(hashProvider, messageUtf8);

        byte[] messageBytes = Array.Empty<byte>();
        byte[] hashBytes = Array.Empty<byte>();
        string hashBase64 = string.Empty;

        try
        {
            messageBytes = Encoding.UTF8.GetBytes(messageUtf8);
            hashBytes = hashProvider.Hash(messageBytes);

            hashBase64 = Convert.ToBase64String(hashBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageBytes);
            CryptographicOperations.ZeroMemory(hashBytes);
        }

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
