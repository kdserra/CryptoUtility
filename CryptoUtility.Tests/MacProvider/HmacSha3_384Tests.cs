namespace CryptoUtility.Tests;

public class HmacSha3_384Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha3_384Impl.Shared;
}
