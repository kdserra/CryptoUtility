using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyHmacMd5Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacMd5Impl.Shared;
}
