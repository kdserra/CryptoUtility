using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemSha3_512Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha3_512Impl();
}
