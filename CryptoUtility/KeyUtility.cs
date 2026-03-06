using System.Security.Cryptography;

namespace CryptoUtility;

public static class KeyUtility
{
    public static void GenerateKey()
    {
        var aes = new Aes256GcmCryptoProvider();
    }
}
