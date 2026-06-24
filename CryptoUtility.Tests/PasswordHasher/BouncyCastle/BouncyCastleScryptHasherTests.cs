using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleScryptHasherTests : PasswordHasherTests
{
    internal override IPasswordHasher Hasher => ScryptImpl.Shared;
}
