using Org.BouncyCastle.Crypto.Parameters;
using BouncyPoly1305 = Org.BouncyCastle.Crypto.Macs.Poly1305;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Poly1305 MAC Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Poly1305Impl : IMacProvider
{
    public static readonly Poly1305Impl Shared = new();

    public int RequiredKeySizeInBytes => 32;

    public int MacSizeInBytes => 16;

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        if (key.Length != RequiredKeySizeInBytes)
        {
            throw new ArgumentException(
                $"Key must be exactly {RequiredKeySizeInBytes} bytes.",
                nameof(key)
            );
        }

        var mac = new BouncyPoly1305();
        mac.Init(new KeyParameter(key));

        mac.BlockUpdate(message, 0, message.Length);

        byte[] output = new byte[MacSizeInBytes];
        mac.DoFinal(output, 0);

        return output;
    }
}
