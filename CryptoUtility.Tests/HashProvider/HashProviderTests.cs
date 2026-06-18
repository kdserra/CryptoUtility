namespace CryptoUtility.Tests;

public abstract class HashProviderTests
{
    internal abstract IHashProvider HashProvider { get; }

    private static readonly byte[] MessageBytes = "test-data"u8.ToArray();
    private const string MessageString = "test-data";

    [Fact]
    public void Hash_ShouldBeDeterministic()
    {
        var first = HashProvider.Hash(MessageBytes);
        var second = HashProvider.Hash(MessageBytes);

        Assert.Equal(first, second);
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
    public void Hash_NullInput_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => HashProvider.Hash(null!));
    }

    [Fact]
    public void Hash_EmptyInput_HandlesOrThrows()
    {
        var result = HashProvider.Hash(Array.Empty<byte>());
        Assert.NotEmpty(result);
    }

    [Fact]
    public void HashBase64_NullHashProvider_ThrowsArgumentNullException()
    {
        IHashProvider nullProvider = null!;
        Assert.Throws<ArgumentNullException>(() => nullProvider.HashBase64(MessageString));
    }

    [Fact]
    public void HashBase64_NullMessage_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => HashProvider.HashBase64(null!));
    }

    [Fact]
    public void HashBase64_EmptyString_ReturnsValidHash()
    {
        var result = HashProvider.HashBase64(string.Empty);
        Assert.False(string.IsNullOrEmpty(result));
    }

    [Fact]
    public void SharedInstance_IsNotNull()
    {
        Assert.NotNull(HashProvider);
    }
}
