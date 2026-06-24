using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleArgon2idHasherTests : PasswordHasherTests
{
    internal override IPasswordHasher Hasher => Argon2idImpl.Shared;
}
