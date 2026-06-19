namespace CryptoUtility.Tests;

public sealed class Pbkdf2Tests : PasswordKdfTests
{
    internal override IPasswordKdf Kdf => Pbkdf2Impl.Shared;
}
