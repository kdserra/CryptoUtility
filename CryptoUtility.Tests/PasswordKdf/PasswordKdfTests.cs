using CryptoUtility;
using Xunit;

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
    public void DeriveKey_WithZeroOrNegativeIterations_Throws()
    {
        string password = "TestPassword123";
        byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8];

        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(password, salt, 0, 32));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(password, salt, -5, 32));
    }

    [Fact]
    public void DeriveKey_WithZeroOrNegativeOutputLength_Throws()
    {
        string password = "TestPassword123";
        byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8];

        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(password, salt, 1000, -5));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(password, salt, 1000, 0));
    }

    [Fact]
    public void PasswordKdfExtensions_NullHandling()
    {
        IPasswordKdf? nullKdf = null;

        Assert.False(nullKdf!.TryDeriveKey("pass", [1, 2], 1, 16, out _));
        Assert.False(nullKdf!.TryDeriveKeyBase64("pass", "c2FsdA==", 1, 16, out _));
    }

    [Fact]
    public void DeriveKeyBase64_WithInvalidInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64(null!, "c2FsdA==", 1000, 16));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64("pass", null!, 1000, 16));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64("pass", "invalid_base64", 1000, 16));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64("pass", "c2FsdA==", 0, 16));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64("pass", "c2FsdA==", 1000, -5));
    }
}
