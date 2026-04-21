using System.Text;
using CryptoUtility;

Console.Clear();

OutputCipherBase64Results();
OutputCipherByteResults();
OutputHashBase64Results();
OutputHashByteResults();

void OutputCipherBase64Results()
{
    Console.WriteLine($"------------ CIPHER BASE 64 ------------");
    Console.WriteLine();

    var key = Aes256Gcm.GenerateKeyBase64();
    string plaintext1 = "Hello, world!";

    (_, string encrypted1) = Aes256Gcm.EncryptBase64(key, plaintext1);
    (_, string plaintext2) = Aes256Gcm.DecryptBase64(key, encrypted1);

    Console.WriteLine($"------------ Symmetric ------------");
    Console.WriteLine($"Key: {key}");
    Console.WriteLine($"Plaintext 1: {plaintext1}");
    Console.WriteLine($"Encrypted 1: {encrypted1}");
    Console.WriteLine($"Plaintext 2: {plaintext2}");

    // Asymmetric
    // -----------

    (string publicKey, string secretKey) = Rsa2048.GenerateKeyPairBase64();
    (_, string encrypted2) = Rsa2048.EncryptBase64(publicKey, plaintext1);
    (_, string plaintext3) = Rsa2048.DecryptBase64(secretKey, encrypted2);

    Console.WriteLine();
    Console.WriteLine();
    Console.WriteLine();
    Console.WriteLine($"------------ Asymmetric ------------");
    Console.WriteLine($"Public Key: {publicKey}\n");
    Console.WriteLine($"Secret Key: {secretKey}\n");

    Console.WriteLine($"Plaintext 1: {plaintext1}");
    Console.WriteLine($"Encrypted 2: {encrypted2}");
    Console.WriteLine($"Plaintext 3: {plaintext3}");

    // Sign, and Verify
    (_, string signature) = Rsa2048.SignBase64(plaintext1, secretKey);
    bool isValid = Rsa2048.VerifyBase64(plaintext1, signature, publicKey);

    Console.WriteLine();
    Console.WriteLine();
    Console.WriteLine();
    Console.WriteLine($"------------ Sign & Verify ------------");
    Console.WriteLine($"Signature: {signature}");
    Console.WriteLine($"IsValid: {isValid}");
    Console.WriteLine();
}

void OutputCipherByteResults()
{
    Console.WriteLine($"------------ CIPHER RAW BYTES ------------");
    Console.WriteLine();

    var key = Aes256Gcm.GenerateKey();
    byte[] plaintext1 = Encoding.UTF8.GetBytes("Hello, world!");

    (_, byte[] encrypted1) = Aes256Gcm.Encrypt(key, plaintext1);
    (_, byte[] plaintext2) = Aes256Gcm.Decrypt(key, encrypted1);

    Console.WriteLine($"------------ Symmetric ------------");
    Console.WriteLine($"Key: {key.Format()}");
    Console.WriteLine($"Plaintext 1: {plaintext1.Format()}");
    Console.WriteLine($"Encrypted 1: {encrypted1.Format()}");
    Console.WriteLine($"Plaintext 2: {plaintext2.Format()}");

    // Asymmetric
    // -----------

    (byte[] publicKey, byte[] secretKey) = Rsa2048.GenerateKeyPair();
    (_, byte[] encrypted2) = Rsa2048.Encrypt(publicKey, plaintext1);
    (_, byte[] plaintext3) = Rsa2048.Decrypt(secretKey, encrypted2);

    Console.WriteLine();
    Console.WriteLine();
    Console.WriteLine();
    Console.WriteLine($"------------ Asymmetric ------------");
    Console.WriteLine($"Public Key: {publicKey.Format()}\n");
    Console.WriteLine($"Secret Key: {secretKey.Format()}\n");

    Console.WriteLine($"Plaintext 1: {plaintext1.Format()}");
    Console.WriteLine($"Encrypted 2: {encrypted2.Format()}");
    Console.WriteLine($"Plaintext 3: {plaintext3.Format()}");

    // Sign, and Verify
    (_, byte[] signature) = Rsa2048.Sign(plaintext1, secretKey);
    bool isValid = Rsa2048.Verify(plaintext1, signature, publicKey);

    Console.WriteLine();
    Console.WriteLine();
    Console.WriteLine();
    Console.WriteLine($"------------ Sign & Verify ------------");
    Console.WriteLine($"Signature: {signature.Format()}");
    Console.WriteLine($"IsValid: {isValid}");
    Console.WriteLine();
}

void OutputHashBase64Results()
{
    Console.WriteLine($"------------ HASH BASE64 ------------");
    Console.WriteLine();

    var secretKey = "my secret key";
    var message = "Hello, world!";

    Console.WriteLine($"Key: {secretKey}");
    Console.WriteLine($"Hash: {message}");

    var hash = Sha256.HashBase64(message);
    Console.WriteLine($"Hash: {hash}");

    var signature = Sha256.SignBase64(message, secretKey);
    Console.WriteLine($"Signature: {signature}");

    var isValidSignature = Sha256.VerifyBase64(message, signature, secretKey);
    Console.WriteLine($"Valid Signature: {isValidSignature}");

    Console.WriteLine();
}
void OutputHashByteResults()
{
    Console.WriteLine($"------------ HASH RAW BYTES ------------");
    Console.WriteLine();

    byte[] secretKey = "my secret key"u8.ToArray();
    byte[] message = "Hello, world!"u8.ToArray();

    Console.WriteLine($"Key: {secretKey.Format()}");
    Console.WriteLine($"Hash: {message.Format()}");

    var hash = Sha256.Hash(message);
    Console.WriteLine($"Hash: {hash.Format()}");

    var signature = Sha256.Sign(message, secretKey);
    Console.WriteLine($"Signature: {signature.Format()}");

    var isValidSignature = Sha256.Verify(message, signature, secretKey);
    Console.WriteLine($"Valid Signature: {isValidSignature}");

    Console.WriteLine();
}

public static class Extensions
{
    public static string Format(this byte[]? bytes)
    {
        if (bytes == null || bytes.Length == 0)
            return string.Empty;

        var sb = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
            sb.Append(b.ToString("x2"));

        return sb.ToString();
    }
}
