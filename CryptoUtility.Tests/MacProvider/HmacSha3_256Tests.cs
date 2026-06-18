namespace CryptoUtility.Tests;

public class HmacSha3_256Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha3_256Impl.Shared;
}
