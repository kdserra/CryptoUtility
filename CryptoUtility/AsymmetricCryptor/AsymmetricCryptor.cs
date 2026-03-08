using System.Text;

namespace CryptoUtility;

/// <summary>
/// <para><b>Asymmetric cryptors</b></para>
/// <list type="bullet">
/// <item><description>Encrypt using a public key, decrypt using a private key.</description></item>
/// <item><description>Sign messages using the private key, verify them with the public key.</description></item>
/// <item><description>Always buffered.</description></item>
/// </list>
/// </summary>
public abstract class AsymmetricCryptor
{
    /// <summary>
    /// Gets the size, in bytes, of the cryptographic key used for encryption and decryption operations.
    /// </summary>
    public abstract int KeySizeBytes { get; }

    /// <summary>
    /// Generates a new cryptographic key for use in encryption or decryption operations.
    /// </summary>
    /// <returns>A byte array containing the generated cryptographic key.</returns>
    public abstract (byte[] PublicKey, byte[] SecretKey) GenerateKey();

    /// <summary>
    /// Generates a new cryptographic key and returns it as a Base64 encoded string.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <returns>The generated key as a Base64 string.</returns>
    public (string PublicKey, string SecretKey) GenerateKeyBase64()
    {
        (byte[] PublicKeyBytes, byte[] SecretKeyBytes) keyPair = GenerateKey();
        string publicKeyBase64 = Convert.ToBase64String(keyPair.PublicKeyBytes);
        string secretKeyBase64 = Convert.ToBase64String(keyPair.SecretKeyBytes);
        return (publicKeyBase64, secretKeyBase64);
    }

    public abstract byte[] Encrypt(byte[] publicKey, byte[] value);

    public abstract byte[] Decrypt(byte[] secretKey, byte[] encryptedValue);

    public abstract byte[] Sign(byte[] input, byte[] secretKey);

    public abstract bool Verify(byte[] input, byte[] signature, byte[] publicKey);

    public string EncryptBase64(string publicKey, string value)
    {
        byte[] publicKeyBytes = Encoding.UTF8.GetBytes(publicKey);
        byte[] valueBytes = Encoding.UTF8.GetBytes(value);
        byte[] encryptedValue = Encrypt(publicKeyBytes, valueBytes);
        string encryptedValueBase64 = Convert.ToBase64String(encryptedValue);

        return encryptedValueBase64;
    }

    public string DecryptBase64(string secretKey, string encryptedValue)
    {
        byte[] secretKeyBytes = Encoding.UTF8.GetBytes(secretKey);
        byte[] encryptedValueBytes = Convert.FromBase64String(encryptedValue);
        byte[] originalValueBytes = Decrypt(secretKeyBytes, encryptedValueBytes);
        string originalValue = Encoding.UTF8.GetString(originalValueBytes);

        return originalValue;
    }
}
