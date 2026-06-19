using BouncyPbkdf2Impl = CryptoUtility.BouncyCastle.Pbkdf2Impl;

namespace CryptoUtility.Tests;

public sealed class BouncyPbkdf2Tests : PasswordKdfTests
{
    internal override IPasswordKdf Kdf => BouncyPbkdf2Impl.Shared;
}
