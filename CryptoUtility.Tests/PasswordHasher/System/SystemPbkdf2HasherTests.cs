using CryptoUtility.System;

namespace CryptoUtility.Tests;

public sealed class SystemPbkdf2HasherTests : PasswordHasherTests
{
    internal override IPasswordHasher Hasher => Pbkdf2Impl.Shared;
}
