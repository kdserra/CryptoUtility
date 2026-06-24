using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle HKDF implementation.
/// </summary>
[GenerateStaticApi]
public sealed class HkdfImpl : IKeyExpansionKdf
{
    /// <summary>
    /// Shared static instance of <see cref="HkdfImpl"/>.
    /// </summary>
    public static readonly HkdfImpl Shared = new();

    private HkdfImpl() { }

    /// <inheritdoc />
    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int outputLength,
        byte[] salt,
        byte[] info
    )
    {
        return DeriveKey(
            inputKeyMaterial,
            outputLength,
            salt,
            info,
            new Sha256Digest()
        );
    }

    /// <summary>
    /// Derives a key of the specified length using custom digest parameters.
    /// </summary>
    /// <param name="inputKeyMaterial">The input key material.</param>
    /// <param name="outputLength">The output key length in bytes.</param>
    /// <param name="salt">The salt value.</param>
    /// <param name="info">The context info bytes.</param>
    /// <param name="digest">The underlying hash engine.</param>
    /// <returns>A byte array containing the derived key.</returns>
    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int outputLength,
        byte[] salt,
        byte[] info,
        IDigest digest
    )
    {
        LibraryHelper.ThrowIfAnyNull(inputKeyMaterial, salt);
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLength));

        var hkdf = new HkdfBytesGenerator(digest);
        hkdf.Init(new HkdfParameters(inputKeyMaterial, salt, info));

        byte[] result = new byte[outputLength];
        hkdf.GenerateBytes(result, 0, outputLength);

        return result;
    }
}
