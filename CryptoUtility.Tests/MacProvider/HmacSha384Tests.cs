namespace CryptoUtility.Tests;

public class HmacSha384Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha384Impl.Shared;
}
