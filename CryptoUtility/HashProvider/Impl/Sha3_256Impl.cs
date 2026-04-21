#if NET8_0_OR_GREATER
namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Sha3_256Impl : ShaBase
{
    internal static readonly Sha3_256Impl Shared = new();

    public Sha3_256Impl()
        : base(ShaVariant.Sha3_256) { }
}
#endif
