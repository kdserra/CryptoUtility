using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle MD5 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Md5Impl : IHashProvider
{
    public static readonly Md5Impl Shared = new();

    public byte[] Hash(byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(message);

        MD5Digest digest = new();
        digest.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        return result;
    }
}
