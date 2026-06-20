using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemMd5Tests : HashProviderTests
{
    internal override IHashProvider HashProvider => Md5Impl.Shared;
}
