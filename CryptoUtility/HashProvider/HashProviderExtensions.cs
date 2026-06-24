using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;
    /// <summary>
    /// Provides extension methods for simplified cryptographic hashing operations.
    /// </summary>

public static class HashProviderExtensions
{
    /// <summary>
    /// Computes the cryptographic hash of the specified input data using Base64-encoded strings.
    /// </summary>
    /// <param name="hashProvider">The hash provider instance.</param>
    /// <param name="messageUtf8">The input UTF-8 encoded string.</param>
    /// <returns>A string containing the result.</returns>
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
    /// <summary>
    /// Attempts to computes the cryptographic hash of the specified input data.
    /// </summary>
    /// <param name="hashProvider">The hash provider instance.</param>
    /// <param name="message">The input data to process.</param>
    /// <param name="hash">When this method returns, contains the computed hash.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>

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
    /// <summary>
    /// Attempts to computes the cryptographic hash of the specified input data using base64-encoded strings.
    /// </summary>
    /// <param name="hashProvider">The hash provider instance.</param>
    /// <param name="messageUtf8">The input UTF-8 encoded string.</param>
    /// <param name="hashBase64">When this method returns, contains the Base64-encoded hash.</param>
    /// <returns>true if the operation succeeded; otherwise, false.</returns>

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
