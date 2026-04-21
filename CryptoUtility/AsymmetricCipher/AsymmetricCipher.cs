using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptoUtility;

/// <summary>
/// Defines an asymmetric cipher that performs public key cryptography.
/// </summary>
internal abstract class AsymmetricCipher
{
    /// <summary>
    /// Gets the identifier for the asymmetric cipher algorithm associated with this instance.
    /// </summary>
    public abstract AsymmetricCipherID CipherID { get; }

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

    public abstract (bool success, byte[] signature) Sign(byte[] message, byte[] secretKey);

    public abstract bool Verify(byte[] message, byte[] signature, byte[] publicKey);

    /// <summary>
    /// Encrypts the specified plaintext UTF8 string using the provided Base64 public key and returns whether it
    /// succeeded, and the encrypted result in Base64.
    /// </summary>
    /// <param name="publicKey">Base64 key, use <see cref="AsymmetricCipher.GenerateKeyPairBase64"/> to easily generate.</param>
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

    public (bool success, string signature) SignBase64(string message, string secretKey)
    {
        if (!Helper.NotNull(message, secretKey))
        {
            return (false, string.Empty);
        }

        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);

        (bool success, byte[] signatureBytes) = Sign(messageBytes, secretKeyBytes);
        string signature = Convert.ToBase64String(signatureBytes);

        return (success, signature);
    }

    public bool VerifyBase64(string message, string signature, string publicKey)
    {
        if (!Helper.NotNull(message, signature, publicKey))
        {
            return false;
        }

        byte[] messageBytes = Encoding.UTF8.GetBytes(message);
        byte[] signatureBytes = Convert.FromBase64String(signature);
        byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
        bool isValid = Verify(messageBytes, signatureBytes, publicKeyBytes);

        return isValid;
    }

    /// <summary>
    /// Generates a new cryptographic key for use in encryption or decryption operations.
    /// </summary>
    /// <returns>A byte array containing the generated cryptographic key.</returns>
    public abstract (byte[] PublicKey, byte[] SecretKey) GenerateKeyPair();

    /// <summary>
    /// Generates a new cryptographic key and returns it as a Base64 encoded string.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <returns>The generated key as a Base64 string.</returns>
    public (string PublicKey, string SecretKey) GenerateKeyPairBase64()
    {
        (byte[] PublicKeyBytes, byte[] SecretKeyBytes) keyPair = GenerateKeyPair();
        string publicKeyBase64 = Convert.ToBase64String(keyPair.PublicKeyBytes);
        string secretKeyBase64 = Convert.ToBase64String(keyPair.SecretKeyBytes);
        return (publicKeyBase64, secretKeyBase64);
    }

    internal (bool success, byte[] encrypted) HybridEncrypt(
        SymmetricCipher cipher,
        byte[] publicKey,
        byte[] plaintext
    )
    {
        if (!Helper.NotNullOrEmpty(cipher, publicKey, plaintext))
        {
            return (false, Array.Empty<byte>());
        }

        byte[] asymmetricPlaintextDataEncryptionKey = cipher.GenerateKey();
        (bool success1, byte[] asymmetricEncrypted) = Encrypt(
            publicKey,
            asymmetricPlaintextDataEncryptionKey
        );

        if (!success1)
        {
            return (false, Array.Empty<byte>());
        }

        (bool success2, byte[] symmetricEncrypted) = cipher.Encrypt(
            asymmetricPlaintextDataEncryptionKey,
            plaintext
        );
        if (!success2)
        {
            return (false, Array.Empty<byte>());
        }

        HybridCipherEnvelope envelope = new(
            HybridCipherEnvelope.LatestVersion,
            asymmetricCipherID: CipherID,
            symmetricCipherID: cipher.CipherID,
            asymmetricEncrypted,
            symmetricEncrypted
        );

        return (true, envelope.ToBytes());
    }

    internal (bool success, byte[] plaintext) HybridDecrypt(
        SymmetricCipher cipher,
        byte[] secretKey,
        byte[] encrypted
    )
    {
        if (!Helper.NotNullOrEmpty(cipher, secretKey, encrypted))
        {
            return (false, Array.Empty<byte>());
        }

        HybridCipherEnvelope? envelope = HybridCipherEnvelope.FromBytes(encrypted);
        if (envelope == null)
        {
            return (false, Array.Empty<byte>());
        }

        if (
            envelope.AsymmetricCipherID != CipherID
            || envelope.SymmetricCipherID != cipher.CipherID
        )
        {
            return (false, Array.Empty<byte>());
        }

        (bool success1, byte[] asymmetricPlaintextDataEncryptionKey) = Decrypt(
            secretKey,
            envelope.AsymmetricEncrypted
        );

        if (!success1 || asymmetricPlaintextDataEncryptionKey.IsNullOrEmpty())
        {
            return (false, Array.Empty<byte>());
        }

        (bool success2, byte[] symmetricPlaintext) = cipher.Decrypt(
            asymmetricPlaintextDataEncryptionKey,
            envelope.SymmetricEncrypted
        );

        if (!success2 || symmetricPlaintext.IsNullOrEmpty())
        {
            return (false, Array.Empty<byte>());
        }

        return (true, symmetricPlaintext);
    }

    public (bool success, byte[] encrypted) HybridEncrypt(
        byte[] publicKey,
        byte[] plaintext,
        SymmetricCipherID cipherID = SymmetricCipherID.Aes256GcmSystem
    )
    {
        SymmetricCipher? cipher = Helper.GetSymmetricCipherFromID(cipherID);
        if (cipher == null)
        {
            return (false, Array.Empty<byte>());
        }

        (bool success, byte[] encrypted) result = HybridEncrypt(cipher, publicKey, plaintext);
        return result;
    }

    public (bool success, byte[] plaintext) HybridDecrypt(
        byte[] secretKey,
        byte[] encrypted,
        SymmetricCipherID cipherID = SymmetricCipherID.Aes256GcmSystem
    )
    {
        SymmetricCipher? cipher = Helper.GetSymmetricCipherFromID(cipherID);
        if (cipher == null)
        {
            return (false, Array.Empty<byte>());
        }

        (bool success, byte[] plaintext) result = HybridDecrypt(cipher, secretKey, encrypted);
        return result;
    }

    public (bool success, string encrypted) HybridEncryptBase64(
        string publicKey,
        string plaintext,
        SymmetricCipherID cipherID = SymmetricCipherID.Aes256GcmSystem
    )
    {
        byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        (bool success, byte[] encrypted) = HybridEncrypt(publicKeyBytes, plaintextBytes, cipherID);
        string encryptedBase64 = Convert.ToBase64String(encrypted);
        return (success, encryptedBase64);
    }

    public (bool success, string plaintext) HybridDecryptBase64(
        string secretKey,
        string encrypted,
        SymmetricCipherID cipherID = SymmetricCipherID.Aes256GcmSystem
    )
    {
        byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
        byte[] encryptedBytes = Convert.FromBase64String(encrypted);

        (bool success, byte[] plaintext) result = HybridDecrypt(
            secretKeyBytes,
            encryptedBytes,
            cipherID
        );

        string plaintext = Encoding.UTF8.GetString(result.plaintext);
        return (result.success, plaintext);
    }
}
