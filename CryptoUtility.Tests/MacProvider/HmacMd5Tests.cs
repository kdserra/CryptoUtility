namespace CryptoUtility.Tests;

public class HmacMd5Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacMd5Impl.Shared;
}
