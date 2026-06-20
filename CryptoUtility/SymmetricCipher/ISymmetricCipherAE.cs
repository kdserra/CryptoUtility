namespace CryptoUtility;

public interface ISymmetricCipherAE : ISymmetricCipher
{
    public int AuthTagSizeBytes { get; }
}
