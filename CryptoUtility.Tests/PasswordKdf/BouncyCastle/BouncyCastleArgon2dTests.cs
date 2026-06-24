using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleArgon2dTests : PasswordKdfTests
{
    internal override IPasswordKdf Kdf => Argon2dImpl.Shared;
}
