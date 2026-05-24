#if NET8_0_OR_GREATER
namespace CryptoUtility;

[GenerateStaticApi]
public sealed class Sha3_512Impl : ShaBase
{
    public static readonly Sha3_512Impl Shared = new();

    public Sha3_512Impl()
        : base(ShaVariant.Sha3_512) { }
}
#endif
