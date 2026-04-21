#if NET8_0_OR_GREATER
namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class Sha3_512Impl : ShaBase
{
    internal static readonly Sha3_512Impl Shared = new();

    public Sha3_512Impl()
        : base(ShaVariant.Sha3_512) { }
}
#endif
