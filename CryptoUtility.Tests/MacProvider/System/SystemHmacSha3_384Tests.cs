using CryptoUtility.System;

namespace CryptoUtility.Tests;

public class SystemHmacSha3_384Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha3_384Impl.Shared;
}
