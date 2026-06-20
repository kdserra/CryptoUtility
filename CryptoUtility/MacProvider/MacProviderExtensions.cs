using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

public static class MacProviderExtensions
{
    public static int GetRecommendedKeySizeInBytes(this IMacProvider macProvider)
    {
        if (macProvider.RequiredKeySizeInBytes > 0)
        {
            return macProvider.RequiredKeySizeInBytes;
        }

        return Math.Max(32, macProvider.MacSizeInBytes);
    }

    public static byte[] GenerateKey(this IMacProvider macProvider)
    {
        int keySize = macProvider.GetRecommendedKeySizeInBytes();
        byte[] key = CryptoHelper.GetBytes(keySize);
        return key;
    }

    public static string GenerateKeyBase64(this IMacProvider macProvider)
    {
        byte[] keyBytes = macProvider.GenerateKey();
        string keyBase64 = Convert.ToBase64String(keyBytes);

        CryptographicOperations.ZeroMemory(keyBytes);

        return keyBase64;
    }

    public static string ComputeMacBase64(this IMacProvider macProvider, string key, string message)
    {
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
        byte[] computedMac = macProvider.ComputeMac(key, message);
        bool result = CryptoHelper.FixedTimeEquals(computedMac, mac);

        CryptographicOperations.ZeroMemory(computedMac);

        return result;
    }

    public static bool VerifyBase64(
        this IMacProvider macProvider,
        string key,
        string message,
        string mac
    )
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
}
