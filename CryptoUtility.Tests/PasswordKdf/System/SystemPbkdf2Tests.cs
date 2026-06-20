using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemPbkdf2Tests : PasswordKdfTests
{
    internal override IPasswordKdf Kdf => Pbkdf2Impl.Shared;
}
