using CryptoUtility.System.Extras;

namespace CryptoUtility.Tests;

public sealed class SystemExtrasXxHash128Tests : ChecksumProviderTests
{
    internal override IChecksumProvider ChecksumProvider => XxHash128Impl.Shared;
}
