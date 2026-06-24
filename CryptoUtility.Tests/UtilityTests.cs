using System;
using CryptoUtility;
using Xunit;

namespace CryptoUtility.Tests;

public class UtilityTests
{
    [Fact]
    public void LibraryHelper_ThrowIfNull_ThrowsOnNullWithParamName()
    {
        object? myValue = null;
        var ex = Assert.Throws<ArgumentNullException>(() => LibraryHelper.ThrowIfNull(myValue));
        Assert.Equal("myValue", ex.ParamName);
    }

    [Fact]
    public void LibraryHelper_ThrowIfNull_DoesNotThrowOnNonNull()
    {
        LibraryHelper.ThrowIfNull("test");
        LibraryHelper.ThrowIfNull(123);
        LibraryHelper.ThrowIfNull(new object());
    }

    [Fact]
    public void CryptoHelper_FixedTimeEquals_ReturnsTrueIfEqual()
    {
        byte[] a = [1, 2, 3];
        byte[] b = [1, 2, 3];
        Assert.True(CryptoHelper.FixedTimeEquals(a, b));
    }

    [Fact]
    public void CryptoHelper_FixedTimeEquals_ReturnsFalseIfNotEqual()
    {
        byte[] a = [1, 2, 3];
        byte[] b = [1, 2, 4];
        Assert.False(CryptoHelper.FixedTimeEquals(a, b));
        Assert.False(CryptoHelper.FixedTimeEquals(a, null!));
        Assert.False(CryptoHelper.FixedTimeEquals(a, [1, 2]));
    }
}
