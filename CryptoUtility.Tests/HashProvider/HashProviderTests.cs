using System.Security.Cryptography;
using Xunit;

namespace CryptoUtility.Tests;

public abstract class HashProviderTests
{
    internal abstract HashProvider HashProvider { get; }

    private static readonly byte[] MessageBytes = "test-data"u8.ToArray();
    private static readonly byte[] KeyBytes = "secret-key"u8.ToArray();
    private const string MessageString = "test-data";
    private const string KeyString = "secret-key";

    [Fact]
    public void Hash_ShouldBeDeterministic()
    {
        var first = HashProvider.Hash(MessageBytes);
        var second = HashProvider.Hash(MessageBytes);

        Assert.Equal(first, second);
    }

    [Fact]
    public void Sign_ShouldBeDeterministic_WithDefaultProvider()
    {
        var first = HashProvider.Sign(MessageBytes, KeyBytes);
        var second = HashProvider.Sign(MessageBytes, KeyBytes);

        Assert.Equal(first, second);
    }

    [Fact]
    public void Sign_And_Verify_ShouldReturnTrue_ForValidSignature()
    {
        var signature = HashProvider.Sign(MessageBytes, KeyBytes);
        var result = HashProvider.Verify(MessageBytes, signature, KeyBytes);

        Assert.True(result);
    }

    [Fact]
    public void Verify_ShouldReturnFalse_ForModifiedSignature()
    {
        var signature = HashProvider.Sign(MessageBytes, KeyBytes);
        signature[0] ^= 0xFF;

        var result = HashProvider.Verify(MessageBytes, signature, KeyBytes);

        Assert.False(result);
    }

    [Fact]
    public void Sign_ShouldUseCustomHmacProvider_WhenProvided()
    {
        Func<HMAC> provider = () => new HMACSHA3_512();

        var expected = HashProvider.Sign(MessageBytes, KeyBytes, provider);
        var actual = HashProvider.Sign(MessageBytes, KeyBytes, provider);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void HashBase64_ShouldBeDeterministic()
    {
        var first = HashProvider.HashBase64(MessageString);
        var second = HashProvider.HashBase64(MessageString);

        Assert.Equal(first, second);
    }

    [Fact]
    public void HashBase64_ShouldMatch_ByteHash()
    {
        var expectedBytes = HashProvider.Hash(System.Text.Encoding.UTF8.GetBytes(MessageString));
        var expectedBase64 = Convert.ToBase64String(expectedBytes);

        var actual = HashProvider.HashBase64(MessageString);

        Assert.Equal(expectedBase64, actual);
    }

    [Fact]
    public void SignBase64_ShouldBeDeterministic()
    {
        var first = HashProvider.SignBase64(MessageString, KeyString);
        var second = HashProvider.SignBase64(MessageString, KeyString);

        Assert.Equal(first, second);
    }

    [Fact]
    public void SignBase64_ShouldMatch_ByteSign()
    {
        var expectedBytes = HashProvider.Sign(
            System.Text.Encoding.UTF8.GetBytes(MessageString),
            System.Text.Encoding.UTF8.GetBytes(KeyString)
        );

        var expectedBase64 = Convert.ToBase64String(expectedBytes);

        var actual = HashProvider.SignBase64(MessageString, KeyString);

        Assert.Equal(expectedBase64, actual);
    }

    [Fact]
    public void VerifyBase64_ShouldReturnTrue_ForValidSignature()
    {
        var signature = HashProvider.SignBase64(MessageString, KeyString);

        var result = HashProvider.VerifyBase64(MessageString, signature, KeyString);

        Assert.True(result);
    }

    [Fact]
    public void VerifyBase64_ShouldReturnFalse_ForModifiedSignature()
    {
        var signature = HashProvider.SignBase64(MessageString, KeyString);

        // corrupt base64 by flipping one byte after decoding
        var bytes = Convert.FromBase64String(signature);
        bytes[0] ^= 0xFF;
        var corrupted = Convert.ToBase64String(bytes);

        var result = HashProvider.VerifyBase64(MessageString, corrupted, KeyString);

        Assert.False(result);
    }

    [Fact]
    public void SignBase64_ShouldUseCustomHmacProvider_WhenProvided()
    {
        Func<HMAC> provider = () => new HMACSHA3_512();

        var first = HashProvider.SignBase64(MessageString, KeyString, provider);
        var second = HashProvider.SignBase64(MessageString, KeyString, provider);

        Assert.Equal(first, second);
    }

    [Fact]
    public void VerifyBase64_ShouldUseCustomHmacProvider_WhenProvided()
    {
        Func<HMAC> provider = () => new HMACSHA3_512();

        var signature = HashProvider.SignBase64(MessageString, KeyString, provider);

        var result = HashProvider.VerifyBase64(MessageString, signature, KeyString, provider);

        Assert.True(result);
    }
}
