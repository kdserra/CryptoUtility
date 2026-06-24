using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public class BouncyCastleHmacMd5Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacMd5Impl.Shared;
}
