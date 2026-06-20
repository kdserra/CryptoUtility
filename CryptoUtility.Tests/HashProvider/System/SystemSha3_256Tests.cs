using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemSha3_256Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha3_256Impl();
}
