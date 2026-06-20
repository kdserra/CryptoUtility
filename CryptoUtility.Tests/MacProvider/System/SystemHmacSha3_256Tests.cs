using CryptoUtility.System;

namespace CryptoUtility.Tests;

public class SystemHmacSha3_256Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha3_256Impl.Shared;
}
