namespace CryptoUtility.Tests;

public class HmacSha3_512Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha3_512Impl.Shared;
}
