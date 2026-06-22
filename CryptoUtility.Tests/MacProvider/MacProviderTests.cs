using System;
using System.Text;
using Xunit;

namespace CryptoUtility.Tests;

public abstract class MacProviderTests
{
    internal abstract IMacProvider Mac { get; }

    private byte[] CreateValidKey()
    {
        return Mac.GenerateKey();
    }

    private string CreateValidKeyBase64()
    {
        return Mac.GenerateKeyBase64();
    }

    private string CreateValidMessageBase64()
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes("Hello, World!"));
    }

    [Fact]
    public void ComputeMac_ValidInput_ReturnsExpectedLength()
    {
        // Arrange
        byte[] key = CreateValidKey();
        byte[] message = Encoding.UTF8.GetBytes("Hello, World!");

        // Act
        byte[] result = Mac.ComputeMac(key, message);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(Mac.MacSizeInBytes, result.Length);
    }

    [Fact]
    public void ComputeMacBase64_ValidInput_ReturnsBase64String()
    {
        // Arrange
        string key = CreateValidKeyBase64();
        string message = CreateValidMessageBase64();

        // Act
        string result = Mac.ComputeMacBase64(key, message);

        // Assert
        Assert.False(string.IsNullOrEmpty(result));
        Assert.NotNull(Convert.FromBase64String(result));
    }

    [Fact]
    public void VerifyMac_CorrectMac_ReturnsTrue()
    {
        // Arrange
        byte[] key = CreateValidKey();
        byte[] message = Encoding.UTF8.GetBytes("Hello, World!");
        byte[] mac = Mac.ComputeMac(key, message);

        // Act
        bool isValid = Mac.VerifyMac(key, message, mac);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void VerifyMac_IncorrectMac_ReturnsFalse()
    {
        // Arrange
        byte[] key = CreateValidKey();
        byte[] message = Encoding.UTF8.GetBytes("Hello, World!");
        byte[] tamperedMac = Mac.ComputeMac(key, message);

        if (tamperedMac.Length > 0)
        {
            tamperedMac[0] ^= 0x01;
        }

        // Act
        bool isValid = Mac.VerifyMac(key, message, tamperedMac);

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void VerifyBase64_CorrectMac_ReturnsTrue()
    {
        // Arrange
        string key = CreateValidKeyBase64();
        string message = CreateValidMessageBase64();
        string macBase64 = Mac.ComputeMacBase64(key, message);

        // Act
        bool isValid = Mac.VerifyBase64(key, message, macBase64);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void VerifyBase64_IncorrectMac_ReturnsFalse()
    {
        // Arrange
        string key = CreateValidKeyBase64();
        string message = CreateValidMessageBase64();
        string macBase64 = Mac.ComputeMacBase64(key, message);

        byte[] rawMac = Convert.FromBase64String(macBase64);
        if (rawMac.Length > 0)
        {
            rawMac[0] ^= 0x01;
        }
        string tamperedMacBase64 = Convert.ToBase64String(rawMac);

        // Act
        bool isValid = Mac.VerifyBase64(key, message, tamperedMacBase64);

        // Assert
        Assert.False(isValid);
    }

    [Theory]
    [InlineData(null, "bWVzc2FnZQ==")]
    [InlineData("a2V5", null)]
    public void ComputeMacBase64_NullInputs_Throws(string? key, string? message)
    {
        Assert.ThrowsAny<Exception>(() => Mac.ComputeMacBase64(key!, message!));
    }

    [Fact]
    public void VerifyMac_NullInputs_Throws()
    {
        byte[] validArray = [1, 2, 3];
        Assert.ThrowsAny<Exception>(() => Mac.VerifyMac(null!, validArray, validArray));
        Assert.ThrowsAny<Exception>(() => Mac.VerifyMac(validArray, null!, validArray));
        Assert.ThrowsAny<Exception>(() => Mac.VerifyMac(validArray, validArray, null!));
    }

    [Theory]
    [InlineData(null, "bWVzc2FnZQ==", "bWFj")]
    [InlineData("a2V5", null, "bWFj")]
    [InlineData("a2V5", "bWVzc2FnZQ==", null)]
    public void VerifyBase64_NullInputs_Throws(string? key, string? message, string? mac)
    {
        Assert.ThrowsAny<Exception>(() => Mac.VerifyBase64(key!, message!, mac!));
    }
}
