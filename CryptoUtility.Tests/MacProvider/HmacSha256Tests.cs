namespace CryptoUtility.Tests;

public class HmacSha256Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha256Impl.Shared;
}
