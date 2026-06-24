using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleSha1Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sha1Impl.Shared;
}
