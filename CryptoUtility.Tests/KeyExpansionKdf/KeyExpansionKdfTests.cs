using CryptoUtility;
using Xunit;

namespace CryptoUtility.Tests;

public abstract class KeyExpansionKdfTests
{
    internal abstract IKeyExpansionKdf Kdf { get; }

    private static readonly byte[] MessageBytes = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    private static readonly byte[] SaltBytes = [17, 18, 19, 20];
    private static readonly byte[] InfoBytes = [21, 22, 23, 24];

    [Fact]
    public void DeriveKey_ShouldBeDeterministic()
    {
        byte[] ikm = MessageBytes;
        byte[] salt = SaltBytes;
        byte[] info = InfoBytes;
        int outputLength = 32;

        byte[] first = Kdf.DeriveKey(ikm, outputLength, salt, info);
        byte[] second = Kdf.DeriveKey(ikm, outputLength, salt, info);

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Equal(outputLength, first.Length);
        Assert.Equal(outputLength, second.Length);
        Assert.Equal(first, second);
    }

    [Fact]
    public void KeyExpansionKdfExtensions_NullHandling()
    {
        IKeyExpansionKdf? nullKdf = null;

        Assert.False(nullKdf!.TryDeriveKey([1, 2], 16, [3, 4], [5, 6], out _));
        Assert.False(nullKdf!.TryDeriveKeyBase64("c2Vj", 16, "c2FsdA==", "aW5mbw==", out _));
    }

    [Fact]
    public void DeriveKeyBase64_WithInvalidInputs_Throws()
    {
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64(null!, 16, [1, 2], [3, 4]));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64([1, 2], 16, null!, [3, 4]));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64([1, 2], 16, [1, 2], null!));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKeyBase64([1, 2], -5, [1, 2], [3, 4]));
    }

    [Fact]
    public void DeriveKey_WithZeroOrNegativeOutputLength_Throws()
    {
        byte[] ikm = MessageBytes;
        byte[] salt = SaltBytes;
        byte[] info = InfoBytes;

        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(ikm, -5, salt, info: []));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(ikm, 0, salt, info: []));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(ikm, -5, salt, info));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(ikm, 0, salt, info));
    }
}
