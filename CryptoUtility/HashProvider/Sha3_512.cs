#if NET8_0_OR_GREATER
namespace CryptoUtility;

public sealed class Sha3_512 : ShaHashProvider
{
    public static readonly Sha3_512 Shared = new();

    public Sha3_512()
        : base(ShaVariant.Sha3_512) { }
}
#endif
