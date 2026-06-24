using System;
using Xunit;

namespace CryptoUtility.Tests;

public abstract class PasswordHasherTests
{
    internal abstract IPasswordHasher Hasher { get; }

    [Fact]
    public void HashPassword_Valid_RoundTripVerify()
    {
        string password = "MySecurePassword123!";
        string hash = Hasher.HashPassword(password);
        
        Assert.False(string.IsNullOrEmpty(hash));

        bool matches = Hasher.VerifyPassword(password, hash);
        Assert.True(matches);
    }

    [Fact]
    public void HashPassword_DifferentPassword_VerifyFails()
    {
        string password = "MySecurePassword123!";
        string hash = Hasher.HashPassword(password);

        bool matches = Hasher.VerifyPassword("WrongPassword123!", hash);
        Assert.False(matches);
    }

    [Fact]
    public void HashPassword_WithNullPassword_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Hasher.HashPassword(null!));
    }

    [Fact]
    public void VerifyPassword_WithNullInputs_Throws()
    {
        string hash = Hasher.HashPassword("password");
        
        Assert.ThrowsAny<Exception>(() => Hasher.VerifyPassword(null!, hash));
        Assert.ThrowsAny<Exception>(() => Hasher.VerifyPassword("password", null!));
    }
}
