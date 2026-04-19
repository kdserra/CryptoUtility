#if NET8_0_OR_GREATER
namespace CryptoUtility;

public sealed class Sha3_384 : ShaHashProvider
{
    public static readonly Sha3_384 Shared = new();

    public Sha3_384()
        : base(ShaVariant.Sha3_384) { }
}
#endif
