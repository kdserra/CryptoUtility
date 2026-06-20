using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyHmacSha512Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha512Impl.Shared;
}
