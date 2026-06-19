using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle SHA3_384 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Sha3_384Impl : IHashProvider
{
    public static readonly Sha3_384Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);

        Sha3Digest digest = new(384);
        digest.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        return result;
    }
}
