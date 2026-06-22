using System;
using Xunit;
using CryptoUtility;

namespace CryptoUtility.Tests;

public class UtilityTests
{
    [Fact]
    public void LibraryHelper_ThrowIfAnyNull_ThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => LibraryHelper.ThrowIfAnyNull(null!));
        Assert.Throws<ArgumentNullException>(() => LibraryHelper.ThrowIfAnyNull("ok", null!, "fine"));
    }

    [Fact]
    public void LibraryHelper_ThrowIfAnyNull_DoesNotThrowOnNonNull()
    {
        LibraryHelper.ThrowIfAnyNull("test", 123, new object());
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
