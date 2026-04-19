namespace CryptoUtility;

/// <summary>
/// Official .NET AES-256 GCM
/// </summary>
internal sealed class Aes256GcmImpl : SymmetricCipherAEAD
{
    public override CipherID Cipher => throw new NotImplementedException();

    public override int KeySizeBytes => throw new NotImplementedException();

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
        SymmetricCipherEnvelope? envelope = SymmetricCipherEnvelope.FromBytes(encrypted);
        if (envelope == null)
        {
            return (false, []);
        }

        bool success = Verify(envelope);
        if (!success)
        {
            return (false, []);
        }

        throw new NotImplementedException();
    }
}
