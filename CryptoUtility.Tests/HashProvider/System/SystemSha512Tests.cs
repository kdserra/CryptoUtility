using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemSha512Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Sha512Impl.Shared;
}
