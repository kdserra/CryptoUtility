namespace CryptoUtility;

public interface IKeyExpansionKdf
{
    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info
    );
}
