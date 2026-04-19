namespace CryptoUtility;

/// <summary>
/// Official .NET ChaCha20-Poly1305 Implementation.
/// </summary>
internal sealed class ChaCha20Poly1305Impl : SymmetricCipherAEAD
{
    public override int KeySizeBytes => 32; // 256-bit
    public override int NonceSizeBytes => 12; // 96-bit, recommended size for ChaCha20-Poly1305

    private const int AuthTagSizeBytes = 16; // 128-bit

    public override CipherID CipherID => CipherID.ChaCha20Poly1305;

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
