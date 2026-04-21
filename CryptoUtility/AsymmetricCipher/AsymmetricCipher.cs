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

    /// <summary>
    /// Encrypts the specified plaintext using a hybrid encryption scheme that combines symmetric and asymmetric
    /// encryption methods.
    /// </summary>
    /// <remarks>This method generates a new symmetric encryption key, encrypts it with the provided public
    /// key, and then uses the symmetric key to encrypt the plaintext. The resulting encrypted data includes both the
    /// encrypted symmetric key and the encrypted plaintext. If any step in the process fails, the method returns false
    /// and an empty byte array.</remarks>
    /// <param name="cipher">The symmetric cipher used to encrypt the plaintext. This parameter must not be null.</param>
    /// <param name="publicKey">The public key used to encrypt the symmetric encryption key. This parameter must not be null or empty.</param>
    /// <param name="plaintext">The plaintext data to encrypt. This parameter must not be null or empty.</param>
    /// <returns>A tuple containing a boolean value that indicates whether the encryption was successful, and a byte array
    /// containing the encrypted data. If the encryption fails, the byte array is empty.</returns>
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

    /// <summary>
    /// Attempts to decrypt data that was encrypted using a hybrid encryption scheme, returning the plaintext if
    /// decryption is successful.
    /// </summary>
    /// <remarks>The method validates all input parameters and the integrity of the hybrid cipher envelope
    /// before attempting decryption. Decryption will fail if any validation check does not pass, or if the envelope's
    /// cipher identifiers do not match the expected values.</remarks>
    /// <param name="cipher">The symmetric cipher to use for decrypting the data. This parameter must not be null.</param>
    /// <param name="secretKey">The secret key used to decrypt the asymmetric-encrypted portion of the data. This parameter must not be null or
    /// empty.</param>
    /// <param name="encrypted">The encrypted data to decrypt, provided as a hybrid cipher envelope. This parameter must not be null or empty.</param>
    /// <returns>A tuple containing a boolean that indicates whether decryption was successful, and a byte array containing the
    /// decrypted plaintext. If decryption fails, the boolean is false and the plaintext is an empty array.</returns>
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

    /// <summary>
    /// Encrypts the specified plaintext using a hybrid encryption scheme with the provided public key and symmetric
    /// cipher.
    /// </summary>
    /// <remarks>If the specified cipher ID does not correspond to a supported symmetric cipher, the method
    /// returns false and an empty byte array.</remarks>
    /// <param name="publicKey">The public key used to encrypt the symmetric key. Must be a valid key compatible with the encryption algorithm.</param>
    /// <param name="plaintext">The plaintext data to encrypt. Cannot be null.</param>
    /// <param name="cipherID">The identifier of the symmetric cipher to use for encryption. Defaults to SymmetricCipherID.Aes256GcmSystem if
    /// not specified.</param>
    /// <returns>A tuple containing a value indicating whether the encryption was successful and a byte array with the encrypted
    /// data. The byte array is empty if encryption fails.</returns>
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

    /// <summary>
    /// Decrypts the specified encrypted data using a hybrid cryptographic approach with the provided secret key and
    /// symmetric cipher.
    /// </summary>
    /// <remarks>If the specified cipher identifier does not correspond to a valid symmetric cipher, the
    /// method returns false and an empty plaintext array.</remarks>
    /// <param name="secretKey">The secret key to use for decryption. Must be compatible with the selected symmetric cipher.</param>
    /// <param name="encrypted">The encrypted data to decrypt. This data must have been encrypted using the corresponding hybrid encryption
    /// method.</param>
    /// <param name="cipherID">The identifier of the symmetric cipher to use for decryption. Defaults to SymmetricCipherID.Aes256GcmSystem if
    /// not specified.</param>
    /// <returns>A tuple containing a value indicating whether decryption was successful and the resulting plaintext as a byte
    /// array. The plaintext is empty if decryption fails.</returns>
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

    /// <summary>
    /// Encrypts the specified plaintext using hybrid encryption with the provided public key and returns the result as
    /// a Base64-encoded string.
    /// </summary>
    /// <param name="publicKey">The public key, encoded as a Base64 string, to use for encrypting the plaintext. This key must be valid and
    /// properly formatted.</param>
    /// <param name="plaintext">The plaintext string to encrypt. The string is converted to UTF-8 bytes before encryption.</param>
    /// <param name="cipherID">The symmetric cipher algorithm to use for encryption. Defaults to Aes256GcmSystem if not specified.</param>
    /// <returns>A tuple containing a Boolean value that indicates whether the encryption was successful, and a Base64-encoded
    /// string representing the encrypted data. If encryption fails, the encrypted string will be null or empty.</returns>
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

    /// <summary>
    /// Decrypts a Base64-encoded encrypted string using the specified secret key and symmetric cipher.
    /// </summary>
    /// <param name="secretKey">The Base64-encoded secret key to use for decryption. Must be a valid Base64 string representing the symmetric
    /// key.</param>
    /// <param name="encrypted">The Base64-encoded string containing the encrypted data to decrypt. Must be a valid Base64 string.</param>
    /// <param name="cipherID">The identifier of the symmetric cipher algorithm to use for decryption. Defaults to
    /// SymmetricCipherID.Aes256GcmSystem if not specified.</param>
    /// <returns>A tuple containing a Boolean value that indicates whether decryption was successful, and the decrypted plaintext
    /// string. If decryption fails, the plaintext will be an empty string.</returns>
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
