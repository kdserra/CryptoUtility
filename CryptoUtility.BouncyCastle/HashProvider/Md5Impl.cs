using Org.BouncyCastle.Crypto.Digests;

namespace CryptoUtility.BouncyCastle;

[GenerateStaticApi]
public sealed class Md5Impl : IHashProvider
{
    public byte[] Hash(byte[] message)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        MD5Digest digest = new();
        digest.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);

        return result;
    }
}
