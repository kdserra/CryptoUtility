using CryptoUtility.System.Extras;

namespace CryptoUtility.Tests;

public sealed class SystemExtrasCrc64Tests : ChecksumProviderTests
{
    internal override IChecksumProvider ChecksumProvider => Crc64Impl.Shared;
}
