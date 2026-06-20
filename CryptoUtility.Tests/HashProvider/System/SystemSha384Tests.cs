using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemSha384Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sha384Impl.Shared;
}
