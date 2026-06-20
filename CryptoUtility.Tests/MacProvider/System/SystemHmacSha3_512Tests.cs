using CryptoUtility.System;

namespace CryptoUtility.Tests;

public class SystemHmacSha3_512Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha3_512Impl.Shared;
}
