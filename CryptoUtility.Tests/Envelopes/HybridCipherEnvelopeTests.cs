using System;
using Xunit;

namespace CryptoUtility.Tests;

public class HybridCipherEnvelopeTests
{
    [Fact]
    public void Constructor_WithNullArguments_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new HybridCipherEnvelope(null!, [1, 2]));
        Assert.Throws<ArgumentNullException>(() => new HybridCipherEnvelope([1, 2], null!));
    }

    [Fact]
    public void Properties_ShouldMatchConstructorArguments()
    {
        byte[] asym = [1, 2, 3];
        byte[] sym = [4, 5, 6, 7];

        var envelope = new HybridCipherEnvelope(asym, sym);

        Assert.Equal(asym, envelope.AsymmetricEncrypted);
        Assert.Equal(sym, envelope.SymmetricEncrypted);
    }

    [Fact]
    public void Serialization_Deserialization_RoundTrip()
    {
        byte[] asym = [10, 20, 30, 40];
        byte[] sym = [50, 60, 70, 80, 90];

        var original = new HybridCipherEnvelope(asym, sym);
        byte[] bytes = original.ToBytes();

        Assert.NotNull(bytes);
        Assert.True(bytes.Length >= 4);

        var deserialized = HybridCipherEnvelope.FromBytes(bytes);
        Assert.NotNull(deserialized);
        Assert.Equal(original.AsymmetricEncrypted, deserialized.AsymmetricEncrypted);
        Assert.Equal(original.SymmetricEncrypted, deserialized.SymmetricEncrypted);
    }

    [Fact]
    public void Base64_Serialization_Deserialization_RoundTrip()
    {
        byte[] asym = [1, 2, 3];
        byte[] sym = [4, 5];

        var original = new HybridCipherEnvelope(asym, sym);
        string base64 = original.ToBase64();

        Assert.False(string.IsNullOrEmpty(base64));

        var deserialized = HybridCipherEnvelope.FromBase64(base64);
        Assert.NotNull(deserialized);
        Assert.Equal(original.AsymmetricEncrypted, deserialized.AsymmetricEncrypted);
        Assert.Equal(original.SymmetricEncrypted, deserialized.SymmetricEncrypted);
    }

    [Fact]
    public void FromBytes_WithNullOrShortBytes_ReturnsNull()
    {
        Assert.Null(HybridCipherEnvelope.FromBytes(null!));
        Assert.Null(HybridCipherEnvelope.FromBytes([]));
        Assert.Null(HybridCipherEnvelope.FromBytes([1, 2, 3]));
    }

    [Fact]
    public void FromBytes_WithInvalidLengthHeader_ReturnsNull()
    {
        byte[] invalidBytes = [0, 0, 0, 100, 1];
        Assert.Null(HybridCipherEnvelope.FromBytes(invalidBytes));
    }

    [Fact]
    public void FromBase64_WithNullOrEmpty_ReturnsNull()
    {
        Assert.Null(HybridCipherEnvelope.FromBase64(null!));
        Assert.Null(HybridCipherEnvelope.FromBase64(string.Empty));
        Assert.Null(HybridCipherEnvelope.FromBase64("invalid base64!!!"));
    }
}
