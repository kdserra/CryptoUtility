using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleArgon2dHasherTests : PasswordHasherTests
{
    internal override IPasswordHasher Hasher => Argon2dImpl.Shared;
}
