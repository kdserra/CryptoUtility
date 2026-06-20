using CryptoUtility.System;

namespace CryptoUtility.Tests;

public class SystemHmacSha512Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacSha512Impl.Shared;
}
