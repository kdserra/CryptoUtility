using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemSha256Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sha256Impl.Shared;
}
