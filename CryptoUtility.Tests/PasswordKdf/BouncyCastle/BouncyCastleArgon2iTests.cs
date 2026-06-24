using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleArgon2iTests : PasswordKdfTests
{
    internal override IPasswordKdf Kdf => Argon2iImpl.Shared;
}
