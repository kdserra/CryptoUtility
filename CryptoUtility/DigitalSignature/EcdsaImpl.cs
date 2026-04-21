namespace CryptoUtility;

[GenerateStaticApi]
internal sealed class EcdsaImpl : DigitalSignature
{
    internal static readonly EcdsaImpl Shared = new();

    public override (bool success, byte[] signature) Sign(byte[] message, byte[] secretKey)
    {
        throw new NotImplementedException();
    }

    public override bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        throw new NotImplementedException();
    }
}
