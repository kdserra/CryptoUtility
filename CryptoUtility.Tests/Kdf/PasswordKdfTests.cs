using Xunit;
using CryptoUtility;

namespace CryptoUtility.Tests;

public abstract class PasswordKdfTests
{
    internal abstract IPasswordKdf Kdf { get; }

    [Fact]
    public void DeriveKey_ShouldBeDeterministic()
    {
        string password = "TestPassword123";
        byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8];
        int iterations = 1000;
        int outputLength = 32;

        byte[] first = Kdf.DeriveKey(password, salt, iterations, outputLength);
        byte[] second = Kdf.DeriveKey(password, salt, iterations, outputLength);

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Equal(outputLength, first.Length);
        Assert.Equal(outputLength, second.Length);
        Assert.Equal(first, second);
    }

    [Fact]
    public void DeriveKey_WithZeroOrNegativeIterations_ThrowsOrFails()
    {
        string password = "TestPassword123";
        byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8];

        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(password, salt, 0, 32));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(password, salt, -5, 32));
    }

    [Fact]
    public void DeriveKey_WithZeroOrNegativeOutputLength_ThrowsOrFails()
    {
        string password = "TestPassword123";
        byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8];

        byte[] zeroResult = Kdf.DeriveKey(password, salt, 1000, 0);
        Assert.Empty(zeroResult);

        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(password, salt, 1000, -5));
    }

    [Fact]
    public void PasswordKdfExtensions_NullHandling()
    {
        IPasswordKdf? nullKdf = null;

        string derived = nullKdf!.DeriveKeyBase64("pass", [1, 2], 1, 16);
        Assert.Equal(string.Empty, derived);
    }

    [Fact]
    public void DeriveKeyBase64_WithInvalidInputs_SwallowsAndReturnsEmpty()
    {
        string derived1 = Kdf.DeriveKeyBase64(null!, [1, 2], 1000, 16);
        Assert.Equal(string.Empty, derived1);

        string derived2 = Kdf.DeriveKeyBase64("", [1, 2], 1000, 16);
        Assert.Equal(string.Empty, derived2);

        string derived3 = Kdf.DeriveKeyBase64("pass", null!, 1000, 16);
        Assert.Equal(string.Empty, derived3);

        string derived4 = Kdf.DeriveKeyBase64("pass", [], 1000, 16);
        Assert.Equal(string.Empty, derived4);

        string derived5 = Kdf.DeriveKeyBase64("pass", [1, 2], 0, 16);
        Assert.Equal(string.Empty, derived5);

        string derived6 = Kdf.DeriveKeyBase64("pass", [1, 2], 1000, -5);
        Assert.Equal(string.Empty, derived6);
    }
}
