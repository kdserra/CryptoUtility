using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastlePbkdf2HasherTests : PasswordHasherTests
{
    internal override IPasswordHasher Hasher => Pbkdf2Impl.Shared;
}
