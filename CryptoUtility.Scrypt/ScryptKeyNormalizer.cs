using Sodium;

namespace CryptoUtility.Scrypt;

public sealed class ScryptKeyNormalizer : IKeyNormalizer
{
    private readonly byte[] _salt;
    private readonly long _opsLimit;
    private readonly int _memLimit;

    public ScryptKeyNormalizer(byte[] salt, long opsLimit = 16384, int memLimit = 8 * 1024 * 1024)
    {
        _salt = salt;
        _opsLimit = opsLimit;
        _memLimit = memLimit;
    }

    public byte[] Normalize(byte[] key, int keySize)
    {
        var keyString = Convert.ToBase64String(key);
        var saltString = Convert.ToBase64String(_salt);

        return PasswordHash.ScryptHashBinary(keyString, saltString, _opsLimit, _memLimit, keySize);
    }
}
