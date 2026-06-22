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

    public static string ComputeMacBase64(
        this IMacProvider macProvider,
        string keyBase64,
        string messageUtf8
    )
    {
        byte[] keyBytes = Convert.FromBase64String(keyBase64);
        byte[] messageBytes = Encoding.UTF8.GetBytes(messageUtf8);
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
        try
        {
            byte[] computedMac = macProvider.ComputeMac(key, message);

            bool isValid = CryptoHelper.FixedTimeEquals(computedMac, mac);

            CryptographicOperations.ZeroMemory(computedMac);

            return isValid;
        }
        catch
        {
            return false;
        }
    }

    public static bool VerifyBase64(
        this IMacProvider macProvider,
        string keyBase64,
        string messageUtf8,
        string macBase64
    )
    {
        try
        {
            byte[] keyBytes = Convert.FromBase64String(keyBase64);
            byte[] messageBytes = Encoding.UTF8.GetBytes(messageUtf8);
            byte[] macBytes = Convert.FromBase64String(macBase64);

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

    public static bool TryComputeMac(
        this IMacProvider macProvider,
        byte[] key,
        byte[] message,
        out byte[] mac
    )
    {
        try
        {
            mac = macProvider.ComputeMac(key, message);

            return true;
        }
        catch
        {
            mac = Array.Empty<byte>();

            return false;
        }
    }

    public static bool TryComputeMacBase64(
        this IMacProvider macProvider,
        string keyBase64,
        string messageUtf8,
        out string macBase64
    )
    {
        try
        {
            macBase64 = macProvider.ComputeMacBase64(keyBase64, messageUtf8);

            return true;
        }
        catch
        {
            macBase64 = string.Empty;

            return false;
        }
    }
}
