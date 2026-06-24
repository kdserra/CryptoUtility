using CryptoUtility.System.Extras;

namespace CryptoUtility.Tests;

public sealed class SystemExtrasXxHash64Tests : ChecksumProviderTests
{
    internal override IChecksumProvider ChecksumProvider => XxHash64Impl.Shared;
}
