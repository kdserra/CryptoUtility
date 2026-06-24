using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle HMAC-SHA512 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class HmacSha512Impl : IMacProvider
{
    /// <summary>
    /// Gets the shared instance.
    /// </summary>
    public static readonly HmacSha512Impl Shared = new();

    /// <summary>
    /// Gets the required key size in bytes, or 0 if variable-length keys are accepted.
    /// </summary>
    public int RequiredKeySizeInBytes => 0;

    /// <summary>
    /// Gets the size of the computed MAC in bytes.
    /// </summary>
    public int MacSizeInBytes => 64;

    /// <summary>
    /// Computes the Message Authentication Code (MAC) for the specified message using the provided key.
    /// </summary>
    /// <param name="key">The symmetric key.</param>
    /// <param name="message">The input data to process.</param>
    /// <returns>A byte array containing the result.</returns>
    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        HMac hmac = new(new Sha512Digest());
        hmac.Init(new KeyParameter(key));

        hmac.BlockUpdate(message, 0, message.Length);

        byte[] result = new byte[hmac.GetMacSize()];
        hmac.DoFinal(result, 0);

        return result;
    }
}
