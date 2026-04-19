using System.Security.Cryptography;

namespace CryptoUtility;

[GenerateStaticApi("Xor")]
internal class XorImpl : SymmetricCipher
{
    public override CipherID CipherID => CipherID.Xor;

    public override int KeySizeBytes => 32; // 256-bit

    public override int NonceSizeBytes => 32; // 256-bit

    public override (bool success, byte[] encrypted) Encrypt(
        byte[] key,
        byte[] plaintext,
        byte[] nonce
    )
    {
        byte[] input = new byte[nonce.Length + plaintext.Length];
        Buffer.BlockCopy(nonce, 0, input, 0, nonce.Length);
        Buffer.BlockCopy(plaintext, 0, input, nonce.Length, plaintext.Length);

        byte[] ciphertext = Xor(input, key);

        var envelope = new SymmetricCipherEnvelope(
            version: SymmetricCipherEnvelope.LatestVersion,
            cipher: CipherID.Xor,
            nonce: nonce,
            tag: [],
            aad: [],
            ciphertext: ciphertext
        );

        CryptographicOperations.ZeroMemory(input);

        return (true, envelope.ToBytes());
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

        byte[] decrypted = Xor(envelope.Ciphertext, key);
        if (decrypted.Length < NonceSizeBytes)
        {
            return (false, []);
        }

        byte[] plaintext = new byte[decrypted.Length - NonceSizeBytes];
        Buffer.BlockCopy(decrypted, NonceSizeBytes, plaintext, 0, plaintext.Length);

        return (true, plaintext);
    }

    private static byte[] Xor(byte[] input, byte[] key)
    {
        byte[] output = new byte[input.Length];

        for (int i = 0; i < input.Length; i++)
        {
            output[i] = (byte)(input[i] ^ key[i % key.Length]);
        }

        return output;
    }
}
