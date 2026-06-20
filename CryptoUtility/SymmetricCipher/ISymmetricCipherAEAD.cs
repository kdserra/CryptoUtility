namespace CryptoUtility;

public interface ISymmetricCipherAEAD : ISymmetricCipherAE
{
    public byte[] Encrypt(byte[] key, byte[] plaintext, byte[] nonce, byte[] aad);
}
