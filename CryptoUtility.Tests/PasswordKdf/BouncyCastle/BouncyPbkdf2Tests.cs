using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyPbkdf2Tests : PasswordKdfTests
{
    internal override IPasswordKdf Kdf => Pbkdf2Impl.Shared;
}
