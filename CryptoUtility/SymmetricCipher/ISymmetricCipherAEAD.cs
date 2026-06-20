namespace CryptoUtility;

public interface ISymmetricCipherAEAD : ISymmetricCipherAE
{
    public (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    );
}
