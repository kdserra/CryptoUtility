using System.Text;
using Xunit;

namespace CryptoUtility.Tests;

public abstract class MacProviderTests
{
    internal abstract IMacProvider Mac { get; }

    [Fact]
    public void ComputeMac_ValidInput_ReturnsExpectedLength()
    {
        // Arrange
        byte[] key = Encoding.UTF8.GetBytes("secret-key-12345678901234567890123");
        byte[] message = Encoding.UTF8.GetBytes("Hello, World!");

        // Act
        byte[] result = Mac.ComputeMac(key, message);

        // Assert
        Assert.NotNull(result);
        Assert.NotEmpty(result);
    }

    [Fact]
    public void ComputeMacBase64_ValidInput_ReturnsBase64String()
    {
        // Arrange
        string key = "secret-key-12345678901234567890123";
        string message = "Hello, World!";

        // Act
        string result = Mac.ComputeMacBase64(key, message);

        // Assert
        Assert.False(string.IsNullOrEmpty(result));
        // Verify it is valid Base64
        Assert.NotNull(Convert.FromBase64String(result));
    }

    [Fact]
    public void VerifyMac_CorrectMac_ReturnsTrue()
    {
        // Arrange
        byte[] key = Encoding.UTF8.GetBytes("secret-key-12345678901234567890123");
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
        byte[] key = Encoding.UTF8.GetBytes("secret-key-12345678901234567890123");
        byte[] message = Encoding.UTF8.GetBytes("Hello, World!");
        byte[] tamperedMac = Mac.ComputeMac(key, message);

        if (tamperedMac.Length > 0)
        {
            tamperedMac[0] ^= 0x01; // Tamper with the MAC
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
        string key = "secret-key-12345678901234567890123";
        string message = "Hello, World!";
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
        string key = "secret-key-12345678901234567890123";
        string message = "Hello, World!";
        string macBase64 = Mac.ComputeMacBase64(key, message);
        string tamperedMacBase64 = macBase64.EndsWith("A")
            ? macBase64.Replace("A", "B")
            : macBase64 + "Q==";

        // Act
        bool isValid = Mac.VerifyBase64(key, message, tamperedMacBase64);

        // Assert
        Assert.False(isValid);
    }

    [Theory]
    [InlineData(null, "message")]
    [InlineData("key", null)]
    public void ComputeMacBase64_NullInputs_ReturnsEmptyString(string? key, string? message)
    {
        // Act
        string result = Mac.ComputeMacBase64(key!, message!);

        // Assert
        Assert.Equal(string.Empty, result);
    }

    [Fact]
    public void VerifyMac_NullInputs_ReturnsFalse()
    {
        // Arrange
        byte[] validArray = [1, 2, 3];

        // Assert & Act
        Assert.False(Mac.VerifyMac(null!, validArray, validArray));
        Assert.False(Mac.VerifyMac(validArray, null!, validArray));
        Assert.False(Mac.VerifyMac(validArray, validArray, null!));
    }

    [Theory]
    [InlineData(null, "message", "mac")]
    [InlineData("key", null, "mac")]
    [InlineData("key", "message", null)]
    public void VerifyBase64_NullInputs_ReturnsFalse(string? key, string? message, string? mac)
    {
        // Act
        bool isValid = Mac.VerifyBase64(key!, message!, mac!);

        // Assert
        Assert.False(isValid);
    }
}
