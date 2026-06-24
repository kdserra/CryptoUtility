using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleArgon2iHasherTests : PasswordHasherTests
{
    internal override IPasswordHasher Hasher => Argon2iImpl.Shared;
}
