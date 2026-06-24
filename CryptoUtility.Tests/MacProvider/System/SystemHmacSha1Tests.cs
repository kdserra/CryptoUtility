using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemHmacSha1Tests : MacProviderTests
{
    internal override IMacProvider Mac => HmacSha1Impl.Shared;
}
