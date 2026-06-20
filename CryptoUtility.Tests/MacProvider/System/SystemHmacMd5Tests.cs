using CryptoUtility.System;

namespace CryptoUtility.Tests;

public class SystemHmacMd5Tests : MacProviderTests
{
    internal override IMacProvider Mac { get; } = HmacMd5Impl.Shared;
}
