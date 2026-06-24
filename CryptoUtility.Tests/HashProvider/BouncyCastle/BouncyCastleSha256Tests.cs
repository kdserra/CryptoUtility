using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleSha256Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sha256Impl.Shared;
}
