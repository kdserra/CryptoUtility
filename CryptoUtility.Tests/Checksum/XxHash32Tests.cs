using CryptoUtility.System.Extras;

namespace CryptoUtility.Tests;

public sealed class SystemExtrasXxHash32Tests : ChecksumProviderTests
{
    internal override IChecksumProvider ChecksumProvider => XxHash32Impl.Shared;
}
