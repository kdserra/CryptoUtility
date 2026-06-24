using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleArgon2idTests : PasswordKdfTests
{
    internal override IPasswordKdf Kdf => Argon2idImpl.Shared;
}
