using CryptoUtility.System.Extras;

namespace CryptoUtility.Tests;

public sealed class SystemExtrasCrc32Tests : ChecksumProviderTests
{
    internal override IChecksumProvider ChecksumProvider => Crc32Impl.Shared;
}
