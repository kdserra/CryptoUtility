using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleScryptTests : PasswordKdfTests
{
    internal override IPasswordKdf Kdf => ScryptImpl.Shared;
}
