namespace CryptoUtility.Tests;

public class HmacSha512Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha512Impl.Shared;
}
