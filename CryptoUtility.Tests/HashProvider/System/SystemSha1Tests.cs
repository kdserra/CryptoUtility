using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemSha1Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => new Sha1Impl();
}
