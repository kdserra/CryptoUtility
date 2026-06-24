using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleBlake3Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Blake3Impl.Shared;
}
