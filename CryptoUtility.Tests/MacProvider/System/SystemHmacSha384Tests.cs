using CryptoUtility.System;

namespace CryptoUtility.Tests;

public class SystemHmacSha384Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha384Impl.Shared;
}
