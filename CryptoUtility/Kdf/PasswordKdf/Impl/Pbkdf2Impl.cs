using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Pbkdf2Impl : IPasswordKdf
{
    public static readonly Pbkdf2Impl Shared = new();
    private static readonly HashAlgorithmName DefaultHashAlgorithm = HashAlgorithmName.SHA256;

    public byte[] DeriveKey(byte[] password, byte[] salt, int iterations, int outputLength)
    {
        byte[] key = DerieveKey(password, salt, iterations, outputLength, DefaultHashAlgorithm);
        return key;
    }

    public byte[] DerieveKey(
        byte[] password,
        byte[] salt,
        int iterations,
        int outputLength,
        HashAlgorithmName hashAlgorithm
    )
    {
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
