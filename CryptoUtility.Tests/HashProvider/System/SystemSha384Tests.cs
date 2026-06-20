using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemSha384Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha384Impl();
}
