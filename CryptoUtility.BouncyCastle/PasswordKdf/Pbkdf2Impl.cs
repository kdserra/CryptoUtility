using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

[GenerateStaticApi]
public sealed class Pbkdf2Impl : IPasswordKdf
{
    public static readonly Pbkdf2Impl Shared = new();

    public byte[] DeriveKey(string password, byte[] salt, int iterations, int outputLength)
    {
        return DeriveKey(password, salt, iterations, outputLength, new Sha256Digest());
    }

    public byte[] DeriveKey(
        string password,
        byte[] salt,
        int iterations,
        int outputLength,
        IDigest digest
    )
    {
        LibraryHelper.ThrowIfAnyNull(password, salt);

        if (iterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(iterations));
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLength));

        var gen = new Pkcs5S2ParametersGenerator(digest);

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

        gen.Init(passwordBytes, salt, iterations);

        var keyParam = (KeyParameter)gen.GenerateDerivedMacParameters(outputLength * 8);

        return keyParam.GetKey();
    }
}
