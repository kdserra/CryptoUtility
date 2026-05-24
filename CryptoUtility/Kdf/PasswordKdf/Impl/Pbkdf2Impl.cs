using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Pbkdf2Impl : IPasswordKdf
{
    public static readonly Pbkdf2Impl Shared = new();
    private static readonly HashAlgorithmName DefaultHashAlgorithm = HashAlgorithmName.SHA256;

    public byte[] DeriveKey(string password, byte[] salt, int iterations, int outputLength)
    {
#if NET8_0_OR_GREATER
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(
            password,
            salt,
            iterations,
            DefaultHashAlgorithm,
            outputLength
        );

        return key;
#else
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, iterations, DefaultHashAlgorithm);
        byte[] key = pbkdf2.GetBytes(outputLength);
        return key;
#endif
    }
}
