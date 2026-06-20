using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemSha3_384Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha3_384Impl();
}
