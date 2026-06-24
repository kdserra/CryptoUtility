namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle BIKE-256 Key Encapsulation Mechanism implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Bike256Impl : BikeBase
{
    /// <summary>
    /// The shared BIKE-256 instance.
    /// </summary>
    public static readonly Bike256Impl Shared = new();

    private Bike256Impl()
        : base(Org.BouncyCastle.Pqc.Crypto.Bike.BikeParameters.bike256) { }
}
