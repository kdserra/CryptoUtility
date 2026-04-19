namespace CryptoUtility;

/// <summary>
/// Official .NET ChaCha20-Poly1305 Implementation.
/// </summary>
internal sealed class ChaCha20Poly1305Impl : SymmetricCipherAEAD
{
    private const int NonceSizeBytes = 12;
    private const int TagSizeBytes = 16;

    public override int KeySizeBytes => 32;

    public override CipherID Cipher => CipherID.ChaCha20Poly1305;

    public override (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce,
        byte[] aad
    )
    {
        throw new NotImplementedException();
    }

    public override (bool success, byte[] plaintext) Decrypt(byte[] key, byte[] encrypted)
    {
        throw new NotImplementedException();
    }
}
