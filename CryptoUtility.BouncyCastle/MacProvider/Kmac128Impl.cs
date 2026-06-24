using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle KMAC-128 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Kmac128Impl : IMacProvider
{
    /// <summary>
    /// Shared static instance of <see cref="Kmac128Impl"/>.
    /// </summary>
    public static readonly Kmac128Impl Shared = new();

    private readonly byte[] _customizationString;
    private readonly int _macSize;

    /// <summary>
    /// Initializes a new instance of the <see cref="Kmac128Impl"/> class with defaults.
    /// </summary>
    public Kmac128Impl()
        : this(Array.Empty<byte>(), 32) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="Kmac128Impl"/> class with custom customization string and tag size.
    /// </summary>
    public Kmac128Impl(byte[] customizationString, int macSize)
    {
        _customizationString =
            customizationString ?? throw new ArgumentNullException(nameof(customizationString));
        _macSize = macSize;
    }

    /// <inheritdoc />
    public int RequiredKeySizeInBytes => 0;

    /// <inheritdoc />
    public int MacSizeInBytes => _macSize;

    /// <inheritdoc />
    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        return ComputeMac(key, message, _customizationString, _macSize);
    }

    /// <summary>
    /// Computes the KMAC-128 tag with a custom customization string and tag size.
    /// </summary>
    /// <param name="key">The secret key.</param>
    /// <param name="message">The message to authenticate.</param>
    /// <param name="customizationString">The customization string.</param>
    /// <param name="macSize">The output tag size in bytes.</param>
    /// <returns>The computed KMAC tag.</returns>
    public byte[] ComputeMac(byte[] key, byte[] message, byte[] customizationString, int macSize)
    {
        LibraryHelper.ThrowIfAnyNull(key, message, customizationString);

        var kmac = new KMac(128, customizationString);
        kmac.Init(new KeyParameter(key));
        kmac.BlockUpdate(message, 0, message.Length);

        byte[] output = new byte[macSize];
        kmac.DoFinal(output, 0);

        return output;
    }
}
