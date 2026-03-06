using System.Security.Cryptography;

namespace CryptoUtility;

public class HkdfKeyNormalizer : IKeyNormalizer
{
    private HashAlgorithmName _hashAlgorithm;
    private readonly byte[] _salt;
    private readonly byte[] _info;

    public HkdfKeyNormalizer(HashAlgorithmName hashAlgorithm, byte[] salt, byte[] info)
    {
        _hashAlgorithm = hashAlgorithm;
        _salt = salt;
        _info = info;
    }

    public byte[] Normalize(byte[] key, int keySize)
    {
        var output = new byte[keySize];
        HKDF.DeriveKey(_hashAlgorithm, key, output, _salt, _info);

        return output;
    }
}
