using NaClPoly1305 = NaCl.Core.Poly1305;

namespace CryptoUtility.NaCl;

[GenerateStaticApi]
public sealed class Poly1305Impl : IMacProvider
{
    public static readonly Poly1305Impl Shared = new();

    public int RequiredKeySizeInBytes => 32;

    public int MacSizeInBytes => 16;

    public byte[] ComputeMac(byte[] key, byte[] message)
    {
        LibraryHelper.ThrowIfAnyNull(key, message);

        return NaClPoly1305.ComputeMac(key, message);
    }
}
