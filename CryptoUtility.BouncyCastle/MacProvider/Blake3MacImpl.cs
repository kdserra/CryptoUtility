using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Blake3 Keyed MAC Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Blake3MacImpl : IMacProvider
{
    /// <summary>
    /// Shared static instance of <see cref="Blake3MacImpl"/>.
    /// </summary>
    public static readonly Blake3MacImpl Shared = new();

    private Blake3MacImpl() { }

    /// <inheritdoc />
    public int RequiredKeySizeInBytes => 32; // Blake3 Keyed Mode requires exactly a 32-byte key

    /// <inheritdoc />
    public int MacSizeInBytes => 32;

    /// <inheritdoc />
    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);
        if (key.Length != RequiredKeySizeInBytes)
        {
            throw new ArgumentException(
                $"Key size must be exactly {RequiredKeySizeInBytes} bytes.",
                nameof(key)
            );
        }

        var parameters = Blake3Parameters.Key(key);
        var digest = new Blake3Digest();
        digest.Init(parameters);
        digest.BlockUpdate(message, 0, message.Length);

        byte[] output = new byte[MacSizeInBytes];
        digest.DoFinal(output, 0);

        return output;
    }
}
