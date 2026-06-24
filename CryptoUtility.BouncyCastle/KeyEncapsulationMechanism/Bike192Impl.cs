namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle BIKE-192 Key Encapsulation Mechanism implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Bike192Impl : BikeBase
{
    /// <summary>
    /// The shared BIKE-192 instance.
    /// </summary>
    public static readonly Bike192Impl Shared = new();

    private Bike192Impl() : base(Org.BouncyCastle.Pqc.Crypto.Bike.BikeParameters.bike192) { }
}
