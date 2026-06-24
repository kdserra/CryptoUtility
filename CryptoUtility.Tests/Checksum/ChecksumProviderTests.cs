using System;
using Xunit;

namespace CryptoUtility.Tests;

public abstract class ChecksumProviderTests
{
    internal abstract IChecksumProvider ChecksumProvider { get; }

    private static readonly byte[] MessageBytes = "test-data"u8.ToArray();

    [Fact]
    public void ComputeChecksum_ShouldBeDeterministic()
    {
        var first = ChecksumProvider.ComputeChecksum(MessageBytes);
        var second = ChecksumProvider.ComputeChecksum(MessageBytes);

        Assert.Equal(first, second);
        Assert.Equal(ChecksumProvider.ChecksumSizeInBytes, first.Length);
    }

    [Fact]
    public void ComputeChecksum_NullInput_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => ChecksumProvider.ComputeChecksum(null!));
    }

    [Fact]
    public void ComputeChecksum_EmptyInput_ReturnsValidChecksum()
    {
        var result = ChecksumProvider.ComputeChecksum(Array.Empty<byte>());
        Assert.Equal(ChecksumProvider.ChecksumSizeInBytes, result.Length);
    }

    [Fact]
    public void SharedInstance_IsNotNull()
    {
        Assert.NotNull(ChecksumProvider);
    }
}
