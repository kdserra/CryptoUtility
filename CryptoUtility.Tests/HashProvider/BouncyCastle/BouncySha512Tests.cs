using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncySha512Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sha512Impl.Shared;
}
