using CryptoUtility;
using Xunit;

namespace CryptoUtility.Tests;

public abstract class KeyExpansionKdfTests
{
    internal abstract IKeyExpansionKdf Kdf { get; }

    [Fact]
    public void DeriveKey_ShouldBeDeterministic()
    {
        byte[] ikm = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        byte[] salt = [17, 18, 19, 20];
        byte[] info = [21, 22, 23, 24];
        int iterations = 1;
        int outputLength = 32;

        byte[] first = Kdf.DeriveKey(ikm, iterations, outputLength, salt, info);
        byte[] second = Kdf.DeriveKey(ikm, iterations, outputLength, salt, info);

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

        string derived = nullKdf!.DeriveKeyBase64([1, 2], 1, 16, [3, 4], [5, 6]);
        Assert.Equal(string.Empty, derived);
    }

    [Fact]
    public void DeriveKeyBase64_WithInvalidInputs_SwallowsAndReturnsEmpty()
    {
        string derived1 = Kdf.DeriveKeyBase64(null!, 1, 16, [1, 2], [3, 4]);
        Assert.Equal(string.Empty, derived1);

        string derived2 = Kdf.DeriveKeyBase64([], 1, 16, [1, 2], [3, 4]);
        Assert.Equal(string.Empty, derived2);

        string derived3 = Kdf.DeriveKeyBase64([1, 2], 1, 16, null!, [3, 4]);
        Assert.Equal(string.Empty, derived3);

        string derived4 = Kdf.DeriveKeyBase64([1, 2], 1, 16, [], [3, 4]);
        Assert.Equal(string.Empty, derived4);

        string derived5 = Kdf.DeriveKeyBase64([1, 2], 1, 16, [1, 2], null!);
        Assert.Equal(string.Empty, derived5);

        string derived6 = Kdf.DeriveKeyBase64([1, 2], 1, 16, [1, 2], []);
        Assert.Equal(string.Empty, derived6);

        string derived7 = Kdf.DeriveKeyBase64([1, 2], 1, -5, [1, 2], [3, 4]);
        Assert.Equal(string.Empty, derived7);
    }

    [Fact]
    public void DeriveKey_WithZeroOrNegativeOutputLength_Throws()
    {
        byte[] ikm = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8];
        byte[] info = [1, 2, 3, 4, 5, 6, 7, 8];

        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(ikm, 1000, -5, salt, info: []));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(ikm, 1000, 0, salt, info: []));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(ikm, 1000, -5, salt, info));
        Assert.ThrowsAny<Exception>(() => Kdf.DeriveKey(ikm, 1000, 0, salt, info));
    }
}
