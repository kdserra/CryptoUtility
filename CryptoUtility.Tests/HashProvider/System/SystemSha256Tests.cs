using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemSha256Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha256Impl();
}
