using System.Text;

namespace CryptoUtility;

/// <summary>
/// Defines an asymmetric cipher that performs public key cryptography.
/// </summary>
internal abstract class AsymmetricCipher
{
    /// <summary>
    /// Gets the size, in bytes, of the cryptographic key used for encryption and decryption operations.
    /// </summary>
    public abstract int KeySizeBytes { get; }

    /// <summary>
    /// Gets the size, in bytes, of the cryptographic salt used for encryption and decryption operations.
    /// </summary>
    public abstract int SaltSizeBytes { get; }

    public abstract (bool success, byte[] encrypted) Encrypt(byte[] publicKey, byte[] plaintext);

    public abstract (bool success, byte[] plaintext) Decrypt(byte[] secretKey, byte[] encrypted);

    public abstract (bool success, byte[] signature) Sign(byte[] input, byte[] secretKey);

    public abstract bool Verify(byte[] message, byte[] signature, byte[] publicKey);

    /// <summary>
    /// Encrypts the specified plaintext UTF8 string using the provided Base64 public key and returns whether it
    /// succeeded, and the encrypted result in Base64.
    /// </summary>
    /// <param name="publicKey">Base64 key, use <see cref="AsymmetricCipher.GenerateKeyBase64"/> to easily generate.</param>
    /// <param name="plaintext">Plaintext UTF8 string to encrypt.</param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>
    /// <description><c>success</c>: Indicates whether the encryption operation was successful.</description>
    /// </item>
    /// <item>
    /// <description><c>encrypted</c>: The resulting encrypted base64 string if successful; otherwise, an empty string.</description>
    /// </item>
    /// </list>
    /// </returns>
    public (bool success, string encrypted) EncryptBase64(string publicKey, string plaintext)
    {
        byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        (bool success, byte[] encrypted) encryptedResult = Encrypt(publicKeyBytes, plaintextBytes);

        if (!encryptedResult.success)
        {
            return (false, string.Empty);
        }

        string encryptedBase64 = Convert.ToBase64String(encryptedResult.encrypted);

        return (true, encryptedBase64);
    }

    /// <summary>
    /// Decrypts the specified encrypted bytes using the provided Base64 secret key and returns whether it
    /// succeeded, and the plaintext UTF8 string.
    /// </summary>
    /// <param name="secretKey"></param>
    /// <param name="plaintext"></param>
    /// <returns>
    /// A tuple containing:
    /// <list type="bullet">
    /// <item>
    /// <description><c>success</c>: Indicates whether the decryption operation was successful.</description>
    /// </item>
    /// <item>
    /// <description><c>plaintext</c>: The resulting decrypted plaintext UTF8 string if successful; otherwise, an empty string.</description>
    /// </item>
    /// </list>
    /// </returns>
    public (bool success, string plaintext) DecryptBase64(string secretKey, string encrypted)
    {
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
        byte[] encryptedBytes = Convert.FromBase64String(encrypted);
        (bool success, byte[] plaintext) decryptedResult = Decrypt(secretKeyBytes, encryptedBytes);

        if (!decryptedResult.success)
        {
            return (false, string.Empty);
        }

        string plaintext = Encoding.UTF8.GetString(decryptedResult.plaintext);

        return (true, plaintext);
    }

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
}
