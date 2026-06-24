using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleBcryptHasherTests : PasswordHasherTests
{
    internal override IPasswordHasher Hasher => BcryptImpl.Shared;
}
