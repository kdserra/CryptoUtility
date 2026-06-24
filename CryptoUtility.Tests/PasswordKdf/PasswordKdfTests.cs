using System;
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
        byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        int outputLength = 32;

        byte[] first = Kdf.DeriveKey(password, salt, outputLength);
        byte[] second = Kdf.DeriveKey(password, salt, outputLength);

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Equal(outputLength, first.Length);
        Assert.Equal(outputLength, second.Length);
        Assert.Equal(first, second);
    }

    [Fact]
    public void DeriveKey_WithZeroOrNegativeOutputLength_Throws()
    {
        string password = "TestPassword123";
        byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(password, salt, -5));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(password, salt, 0));
    }

    [Fact]
    public void PasswordKdfExtensions_NullHandling()
    {
        IPasswordKdf? nullKdf = null;

        Assert.False(nullKdf!.TryDeriveKey("pass", [1, 2], 16, out _));
        Assert.False(nullKdf!.TryDeriveKeyBase64("pass", "c2FsdA==", 16, out _));
    }

    [Fact]
    public void DeriveKeyBase64_WithInvalidInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64(null!, "c2FsdA==", 16));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64("pass", null!, 16));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64("pass", "invalid_base64", 16));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64("pass", "c2FsdA==", -5));
    }
}
