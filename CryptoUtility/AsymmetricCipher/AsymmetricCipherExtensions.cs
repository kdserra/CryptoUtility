using System.Text;

namespace CryptoUtility;

public static class AsymmetricCipherExtensions
{
    /// <summary>
    /// Encrypts the specified plaintext UTF8 string using the provided Base64 public key and returns whether it
    /// succeeded, and the encrypted result in Base64.
    /// </summary>
    /// <param name="cipher">The asymmetric cipher used for the encryption operation.</param>
    /// <param name="publicKey">Base64 key, use <see cref="IAsymmetricCipher.GenerateKeyPairBase64"/> to easily generate.</param>
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
    public static (bool success, string encrypted) EncryptBase64(
        this IAsymmetricCipher cipher,
        string publicKey,
        string plaintext
    )
    {
        try
        {
            if (!LibraryHelper.NotNull(cipher, publicKey, plaintext))
            {
                return (false, string.Empty);
            }

            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            (bool success, byte[] encrypted) encryptedResult = cipher.Encrypt(
                publicKeyBytes,
                plaintextBytes
            );

            if (!encryptedResult.success)
            {
                return (false, string.Empty);
            }

            string encryptedBase64 = Convert.ToBase64String(encryptedResult.encrypted);

            return (true, encryptedBase64);
        }
        catch
        {
            return (false, string.Empty);
        }
    }

    /// <summary>
    /// Decrypts the specified encrypted bytes using the provided Base64 secret key and returns whether it
    /// succeeded, and the plaintext UTF8 string.
    /// </summary>
    /// <param name="cipher">The asymmetric cipher used for the decryption operation.</param>
    /// <param name="secretKey">The secret key in Base64 format.</param>
    /// <param name="encrypted">The encrypted ciphertext in Base64 format.</param>
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
    public static (bool success, string plaintext) DecryptBase64(
        this IAsymmetricCipher cipher,
        string secretKey,
        string encrypted
    )
    {
        try
        {
            if (!LibraryHelper.NotNull(cipher, secretKey, encrypted))
            {
                return (false, string.Empty);
            }

            byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
            byte[] encryptedBytes = Convert.FromBase64String(encrypted);

            (bool success, byte[] plaintext) decryptedResult = cipher.Decrypt(
                secretKeyBytes,
                encryptedBytes
            );

            if (!decryptedResult.success)
            {
                return (false, string.Empty);
            }

            string plaintext = Encoding.UTF8.GetString(decryptedResult.plaintext);

            return (true, plaintext);
        }
        catch
        {
            return (false, string.Empty);
        }
    }

    /// <summary>
    /// Generates a new cryptographic key and returns it as a Base64 encoded string.
    /// </summary>
    /// <param name="cipher">The asymmetric cipher instance.</param>
    /// <returns>The generated key as a Base64 string.</returns>
    public static (string PublicKey, string SecretKey) GenerateKeyPairBase64(
        this IAsymmetricCipher cipher
    )
    {
        if (!LibraryHelper.NotNull(cipher))
        {
            return (string.Empty, string.Empty);
        }

        (byte[] PublicKeyBytes, byte[] SecretKeyBytes) keyPair = cipher.GenerateKeyPair();
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
    /// <param name="asymmetricCipher">The asymmetric cipher used to encrypt the data encryption key. This parameter must not be null.</param>
    /// <param name="symmetricCipher">The symmetric cipher used to encrypt the plaintext. This parameter must not be null.</param>
    /// <param name="publicKey">The public key used to encrypt the symmetric encryption key. This parameter must not be null or empty.</param>
    /// <param name="plaintext">The plaintext data to encrypt. This parameter must not be null or empty.</param>
    /// <returns>A tuple containing a boolean value that indicates whether the encryption was successful, and a byte array
    /// containing the encrypted data. If the encryption fails, the byte array is empty.</returns>
    public static (bool success, byte[] encrypted) HybridEncrypt(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        byte[] publicKey,
        byte[] plaintext
    )
    {
        try
        {
            if (
                !LibraryHelper.NotNullOrEmpty(
                    asymmetricCipher,
                    symmetricCipher,
                    publicKey,
                    plaintext
                )
            )
            {
                return (false, Array.Empty<byte>());
            }

            byte[] asymmetricPlaintextDataEncryptionKey = symmetricCipher.GenerateKey();
            (bool asymmetricSuccess, byte[] asymmetricEncrypted) = asymmetricCipher.Encrypt(
                publicKey,
                asymmetricPlaintextDataEncryptionKey
            );

            if (!asymmetricSuccess)
            {
                return (false, Array.Empty<byte>());
            }

            (bool symmetricSuccess, byte[] symmetricEncrypted) = symmetricCipher.Encrypt(
                asymmetricPlaintextDataEncryptionKey,
                plaintext
            );
            if (!symmetricSuccess)
            {
                return (false, Array.Empty<byte>());
            }

            HybridCipherEnvelope envelope = new(
                HybridCipherEnvelope.LatestVersion,
                asymmetricEncrypted,
                symmetricEncrypted
            );

            return (true, envelope.ToBytes());
        }
        catch
        {
            return (false, Array.Empty<byte>());
        }
    }

    /// <summary>
    /// Attempts to decrypt data that was encrypted using a hybrid encryption scheme, returning the plaintext if
    /// decryption is successful.
    /// </summary>
    /// <remarks>The method validates all input parameters and the integrity of the hybrid cipher envelope
    /// before attempting decryption. Decryption will fail if any validation check does not pass, or if the envelope's
    /// cipher identifiers do not match the expected values.</remarks>
    /// <param name="asymmetricCipher">The asymmetric cipher used to encrypt the data encryption key. This parameter must not be null.</param>
    /// <param name="symmetricCipher">The symmetric cipher to use for decrypting the data. This parameter must not be null.</param>
    /// <param name="secretKey">The secret key used to decrypt the asymmetric-encrypted portion of the data. This parameter must not be null or
    /// empty.</param>
    /// <param name="encrypted">The encrypted data to decrypt, provided as a hybrid cipher envelope. This parameter must not be null or empty.</param>
    /// <returns>A tuple containing a boolean that indicates whether decryption was successful, and a byte array containing the
    /// decrypted plaintext. If decryption fails, the boolean is false and the plaintext is an empty array.</returns>
    public static (bool success, byte[] plaintext) HybridDecrypt(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher symmetricCipher,
        byte[] secretKey,
        byte[] encrypted
    )
    {
        try
        {
            if (
                !LibraryHelper.NotNullOrEmpty(
                    asymmetricCipher,
                    symmetricCipher,
                    secretKey,
                    encrypted
                )
            )
            {
                return (false, Array.Empty<byte>());
            }

            HybridCipherEnvelope? envelope = HybridCipherEnvelope.FromBytes(encrypted);
            if (envelope == null)
            {
                return (false, Array.Empty<byte>());
            }

            (bool asymmetricSuccess, byte[] asymmetricPlaintextDataEncryptionKey) =
                asymmetricCipher.Decrypt(secretKey, envelope.AsymmetricEncrypted);

            if (!asymmetricSuccess || asymmetricPlaintextDataEncryptionKey.IsNullOrEmpty())
            {
                return (false, Array.Empty<byte>());
            }

            (bool symmetricSuccess, byte[] symmetricPlaintext) = symmetricCipher.Decrypt(
                asymmetricPlaintextDataEncryptionKey,
                envelope.SymmetricEncrypted
            );

            if (!symmetricSuccess || symmetricPlaintext.IsNullOrEmpty())
            {
                return (false, Array.Empty<byte>());
            }

            return (true, symmetricPlaintext);
        }
        catch
        {
            return (false, Array.Empty<byte>());
        }
    }

    /// <summary>
    /// Encrypts the specified plaintext using hybrid encryption with the provided public key and returns the result as
    /// a Base64-encoded string.
    /// </summary>
    /// <param name="asymmetricCipher">The asymmetric cipher used to encrypt the data encryption key. This parameter must not be null.</param>
    /// <param name="publicKey">The public key, encoded as a Base64 string, to use for encrypting the plaintext. This key must be valid and
    /// properly formatted.</param>
    /// <param name="plaintext">The plaintext string to encrypt. The string is converted to UTF-8 bytes before encryption.</param>
    /// <param name="cipher">The symmetric cipher algorithm to use for encryption. Defaults to Aes256GcmImpl.Shared if not specified.</param>
    /// <returns>A tuple containing a Boolean value that indicates whether the encryption was successful, and a Base64-encoded
    /// string representing the encrypted data. If encryption fails, the encrypted string will be null or empty.</returns>
    public static (bool success, string encrypted) HybridEncryptBase64(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher cipher,
        string publicKey,
        string plaintext
    )
    {
        try
        {
            if (!LibraryHelper.NotNullOrEmpty(asymmetricCipher, publicKey, plaintext))
            {
                return (false, string.Empty);
            }

            byte[] publicKeyBytes = Convert.FromBase64String(publicKey);
            byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

            (bool success, byte[] encrypted) = HybridEncrypt(
                asymmetricCipher,
                cipher,
                publicKeyBytes,
                plaintextBytes
            );

            string encryptedBase64 = Convert.ToBase64String(encrypted);

            return (success, encryptedBase64);
        }
        catch
        {
            return (false, string.Empty);
        }
    }

    /// <summary>
    /// Decrypts a Base64-encoded encrypted string using the specified secret key and symmetric cipher.
    /// </summary>
    /// <param name="asymmetricCipher">The asymmetric cipher used to encrypt the data encryption key. This parameter must not be null.</param>
    /// <param name="secretKey">The Base64-encoded secret key to use for decryption. Must be a valid Base64 string representing the symmetric
    /// key.</param>
    /// <param name="encrypted">The Base64-encoded string containing the encrypted data to decrypt. Must be a valid Base64 string.</param>
    /// <param name="cipher">The symmetric cipher algorithm to use for decryption. Defaults to
    /// Aes256GcmImpl.Shared if not specified.</param>
    /// <returns>A tuple containing a Boolean value that indicates whether decryption was successful, and the decrypted plaintext
    /// string. If decryption fails, the plaintext will be an empty string.</returns>
    public static (bool success, string plaintext) HybridDecryptBase64(
        this IAsymmetricCipher asymmetricCipher,
        ISymmetricCipher cipher,
        string secretKey,
        string encrypted
    )
    {
        try
        {
            cipher ??= Aes256GcmImpl.Shared;

            if (!LibraryHelper.NotNullOrEmpty(asymmetricCipher, secretKey, encrypted))
            {
                return (false, string.Empty);
            }

            byte[] secretKeyBytes = Convert.FromBase64String(secretKey);
            byte[] encryptedBytes = Convert.FromBase64String(encrypted);

            (bool success, byte[] plaintext) result = HybridDecrypt(
                asymmetricCipher,
                cipher,
                secretKeyBytes,
                encryptedBytes
            );

            string plaintext = Encoding.UTF8.GetString(result.plaintext);
            return (result.success, plaintext);
        }
        catch
        {
            return (false, string.Empty);
        }
    }
}
