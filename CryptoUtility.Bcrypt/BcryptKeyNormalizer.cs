using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility.Bcrypt;

public class BcryptKeyNormalizer : IKeyNormalizer
{
    private readonly int _workFactor;

    public BcryptKeyNormalizer(int workFactor = 12)
    {
        _workFactor = workFactor;
    }

    public byte[] Normalize(byte[] key, int keySize)
    {
        string keyString = Convert.ToBase64String(key);
        string hash = BCrypt.Net.BCrypt.HashPassword(keyString, _workFactor);
        byte[] hashBytes = Encoding.UTF8.GetBytes(hash);
        byte[] output = new byte[keySize];

        using var sha256 = SHA256.Create();
        byte[] digest = sha256.ComputeHash(hashBytes);

        for (int i = 0; i < keySize; i++)
            output[i] = digest[i % digest.Length];

        return output;
    }
}
