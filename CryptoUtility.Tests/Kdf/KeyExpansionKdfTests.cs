using Xunit;
using CryptoUtility;

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

        string derived = nullKdf!.DeriveKeyBase64("pass", "salt", "info", 1, 16);
        Assert.Equal(string.Empty, derived);
    }

    [Fact]
    public void DeriveKeyBase64_WithInvalidInputs_SwallowsAndReturnsEmpty()
    {
        string derived1 = Kdf.DeriveKeyBase64(null!, "salt", "info", 1, 16);
        Assert.Equal(string.Empty, derived1);

        string derived2 = Kdf.DeriveKeyBase64("", "salt", "info", 1, 16);
        Assert.Equal(string.Empty, derived2);

        string derived3 = Kdf.DeriveKeyBase64("pass", null!, "info", 1, 16);
        Assert.Equal(string.Empty, derived3);

        string derived4 = Kdf.DeriveKeyBase64("pass", "", "info", 1, 16);
        Assert.Equal(string.Empty, derived4);

        string derived5 = Kdf.DeriveKeyBase64("pass", "salt", null!, 1, 16);
        Assert.Equal(string.Empty, derived5);

        string derived6 = Kdf.DeriveKeyBase64("pass", "salt", "", 1, 16);
        Assert.Equal(string.Empty, derived6);

        string derived7 = Kdf.DeriveKeyBase64("invalid_base64_!", "salt", "info", 1, 16);
        Assert.Equal(string.Empty, derived7);

        string derived8 = Kdf.DeriveKeyBase64("pass", "salt", "info", 1, -5);
        Assert.Equal(string.Empty, derived8);
    }
}
