namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle BIKE-128 Key Encapsulation Mechanism implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Bike128Impl : BikeBase
{
    /// <summary>
    /// The shared BIKE-128 instance.
    /// </summary>
    public static readonly Bike128Impl Shared = new();

    private Bike128Impl()
        : base(
            Org.BouncyCastle.Pqc.Crypto.Bike.BikeParameters.bike128,
            publicKeySizeBytes: 1565,
            secretKeySizeBytes: 3144,
            ciphertextSizeBytes: 1573,
            sharedSecretSizeBytes: 16
        ) { }
}
