using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Pbkdf2Impl : IPasswordKdf
{
    public static readonly Pbkdf2Impl Shared = new();

    public byte[] DeriveKey(string password, byte[] salt, int iterations, int outputLength)
    {
        return DeriveKey(password, salt, iterations, outputLength, HashAlgorithmName.SHA256);
    }

    public byte[] DeriveKey(
        string password,
        byte[] salt,
        int iterations,
        int outputLength,
        HashAlgorithmName hashAlgorithm
    )
    {
        LibraryHelper.ThrowIfAnyNull(password, salt);

        if (iterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(iterations));
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLength));

#if NET8_0_OR_GREATER
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            hashAlgorithm,
            outputLength
        );

        return key;
#else
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, hashAlgorithm);
        byte[] key = pbkdf2.GetBytes(outputLength);
        return key;
#endif
    }
}
