using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

public static class MacProviderExtensions
{
    public static string ComputeMacBase64(this IMacProvider macProvider, string key, string message)
    {
        if (!LibraryHelper.NotNull(macProvider, key, message))
        {
            return string.Empty;
        }

        byte[] keyBytes = Convert.FromBase64String(key);
        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] macBytes = macProvider.ComputeMac(keyBytes, messageBytes);
        string macBase64 = Convert.ToBase64String(macBytes);

        CryptographicOperations.ZeroMemory(keyBytes);
        CryptographicOperations.ZeroMemory(messageBytes);
        CryptographicOperations.ZeroMemory(macBytes);

        return macBase64;
    }

    public static bool VerifyMac(
        this IMacProvider macProvider,
        byte[] key,
        byte[] message,
        byte[] mac
    )
    {
        if (!LibraryHelper.NotNull(macProvider, key, message, mac))
        {
            return false;
        }

        try
        {
            byte[] computedMac = macProvider.ComputeMac(key, message);
            bool result = CryptoHelper.FixedTimeEquals(computedMac, mac);

            CryptographicOperations.ZeroMemory(computedMac);
            return result;
        }
        catch
        {
            return false;
        }
    }

    public static bool VerifyBase64(
        this IMacProvider macProvider,
        string key,
        string message,
        string mac
    )
    {
        if (!LibraryHelper.NotNull(macProvider, key, message, mac))
        {
            return false;
        }

        try
        {
            byte[] keyBytes = Convert.FromBase64String(key);
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            byte[] macBytes = Convert.FromBase64String(mac);
            bool isValid = macProvider.VerifyMac(keyBytes, messageBytes, macBytes);

            CryptographicOperations.ZeroMemory(keyBytes);
            CryptographicOperations.ZeroMemory(messageBytes);
            CryptographicOperations.ZeroMemory(macBytes);

            return isValid;
        }
        catch
        {
            return false;
        }
    }
}
