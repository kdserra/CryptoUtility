using Konscious.Security.Cryptography;

namespace CryptoUtility.Argon2;

public sealed class Argon2KeyNormalizer : IKeyNormalizer
{
    private readonly byte[] _salt;
    private readonly int _iterations;
    private readonly int _memoryKb;
    private readonly int _parallelism;

    public Argon2KeyNormalizer(
        byte[] salt,
        int iterations = 4,
        int memoryKb = 65536,
        int parallelism = 2
    )
    {
        _salt = salt;
        _iterations = iterations;
        _memoryKb = memoryKb;
        _parallelism = parallelism;
    }

    public byte[] Normalize(byte[] key, int keySize)
    {
        var argon2 = new Argon2id(key)
        {
            Salt = _salt,
            Iterations = _iterations,
            MemorySize = _memoryKb,
            DegreeOfParallelism = _parallelism,
        };

        return argon2.GetBytes(keySize);
    }
}
