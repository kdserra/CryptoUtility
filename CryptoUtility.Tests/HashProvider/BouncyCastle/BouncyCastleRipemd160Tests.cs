using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleRipemd160Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Ripemd160Impl.Shared;
}
