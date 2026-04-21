namespace CryptoUtility.Tests;

public class XorTests : SymmetricCipherTests
{
    internal override SymmetricCipher Cipher => new XorCipherImpl();

    void t()
    {
        string b64Key = ChaCha20Poly1305.GenerateKeyBase64();

        (bool success, string encrypted) encResult = ChaCha20Poly1305.EncryptBase64(
            b64Key,
            "Hello, world!"
        );

        if (!encResult.success)
        {
            throw new InvalidOperationException();
        }

        (bool success, string plaintext) decResult = ChaCha20Poly1305.DecryptBase64(
            b64Key,
            encResult.encrypted
        );

        if (!decResult.success)
        {
            throw new InvalidOperationException();
        }
    }
}
