using CryptoUtility.System;

namespace CryptoUtility.Tests;

public class SystemHmacSha256Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha256Impl.Shared;
}
