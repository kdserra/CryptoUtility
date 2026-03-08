using System.Text;

namespace CryptoUtility;

/// <summary>
/// Defines a symmetric cryptor that processes data using either a buffered or incremental strategy.
///
/// <para><b>Symmetric cryptors</b></para>
/// <list type="bullet">
/// <item><description>Encrypt and decrypt using a single key.</description></item>
/// <item><description>Arbitrary keys supported.</description></item>
/// <item><description>Buffered, and incremental operations supported depending on the implementation.</description></item>
/// </list>
///
/// </summary>
/// <remarks>
/// Two processing models exist in this library:
///
/// <para><b>Buffered cryptors</b></para>
/// <list type="bullet">
/// <item><description>Operate on the entire input in a single operation.</description></item>
/// <item><description>Require the full plaintext or ciphertext to be present in memory.</description></item>
/// <item><description>Typically faster due to reduced state management and better hardware acceleration.</description></item>
/// <item><description>Best suited for small to moderately sized data.</description></item>
/// <item><description>Memory usage grows with input size.</description></item>
/// </list>
///
/// Choose the buffered implementation for maximum throughput when the entire payload fits comfortably in memory.
///
/// <para><b>Incremental cryptors</b></para>
/// <list type="bullet">
/// <item><description>Process data in sequential chunks.</description></item>
/// <item><description>Maintain internal state between operations.</description></item>
/// <item><description>Enable encryption or decryption of arbitrarily large streams.</description></item>
/// <item><description>Designed for files, network streams, or other large data sources.</description></item>
/// <item><description>Typically slightly slower due to chunk management and state tracking.</description></item>
/// </list>
///
/// Choose the incremental implementation when working with large data or streaming scenarios.
/// </remarks>
public abstract class SymmetricCryptor
{
    /// <summary>
    /// Gets the size, in bytes, of the cryptographic key used for encryption and decryption operations.
    /// </summary>
    public abstract int KeySizeBytes { get; }

    /// <summary>
    /// Generates a new cryptographic key for use in encryption or decryption operations.
    /// </summary>
    /// <returns>A byte array containing the generated cryptographic key.</returns>
    public virtual byte[] GenerateKey()
    {
        return CryptoHelper.GetBytes(KeySizeBytes);
    }

    /// <summary>
    /// Generates a new cryptographic key and returns it as a Base64 encoded string.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <returns>The generated key as a Base64 string.</returns>
    public string GenerateKeyBase64()
    {
        byte[] key = GenerateKey();
        string result = Convert.ToBase64String(key);
        return result;
    }

    /// <summary>
    /// Encrypts the specified value using the provided key and returns the encrypted data.
    /// </summary>
    /// <param name="key">The cryptographic key used for encryption.</param>
    /// <param name="value">The value to encrypt.</param>
    /// <param name="keyNormalizer">Optional key normalizer. If not provided, a default will be used.</param>
    /// <returns>The encrypted data.</returns>
    public virtual void Encrypt(
        Stream key,
        Stream input,
        Stream output,
        IKeyNormalizer? keyNormalizer = null
    ) => EncryptStreamToBuffer(key, input, output, keyNormalizer);

    /// <summary>
    /// Decrypts the specified encrypted value using the provided key and returns the decrypted data.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <param name="key">The cryptographic key used for decryption.</param>
    /// <param name="encryptedValue">The encrypted value to decrypt.</param>
    /// <param name="keyNormalizer">Optional key normalizer. If not provided, a default will be used.</param>
    /// <returns>The decrypted data.</returns>
    public virtual void Decrypt(
        Stream key,
        Stream input,
        Stream output,
        IKeyNormalizer? keyNormalizer = null
    ) => DecryptStreamToBuffer(key, input, output, keyNormalizer);

    /// <summary>
    /// Encrypts the specified value using the provided key and returns the encrypted data.
    /// </summary>
    /// <param name="key">The cryptographic key used for encryption.</param>
    /// <param name="value">The value to encrypt.</param>
    /// <param name="keyNormalizer">Optional key normalizer. If not provided, a default will be used.</param>
    /// <returns>The encrypted data.</returns>
    public virtual byte[] Encrypt(byte[] key, byte[] value, IKeyNormalizer? keyNormalizer = null) =>
        EncryptBufferToStream(key, value, keyNormalizer);

    /// <summary>
    /// Decrypts the specified encrypted value using the provided key and returns the decrypted data.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <param name="key">The cryptographic key used for decryption.</param>
    /// <param name="encryptedValue">The encrypted value to decrypt.</param>
    /// <param name="keyNormalizer">Optional key normalizer. If not provided, a default will be used.</param>
    /// <returns>The decrypted data.</returns>
    public virtual byte[] Decrypt(
        byte[] key,
        byte[] encryptedValue,
        IKeyNormalizer? keyNormalizer = null
    ) => DecryptBufferToStream(key, encryptedValue, keyNormalizer);

    /// <summary>
    /// Encrypts the specified value using the provided key and returns the encrypted data.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <param name="key">The cryptographic key used for encryption.</param>
    /// <param name="value">The value to encrypt.</param>
    /// <param name="keyNormalizer">Optional key normalizer. If not provided, a default will be used.</param>
    /// <returns>The encrypted data.</returns>
    public string EncryptBase64(string key, string value, IKeyNormalizer? keyNormalizer = null)
    {
        byte[] valueBytes = Encoding.UTF8.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = Encrypt(keyBytes, valueBytes, keyNormalizer);
        string result = Convert.ToBase64String(encryptedBytes);
        return result;
    }

    /// <summary>
    /// Decrypts the specified encrypted value using the provided key and returns the decrypted data.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <param name="key">The cryptographic key used for decryption.</param>
    /// <param name="encryptedValue">The encrypted value to decrypt.</param>
    /// <param name="keyNormalizer">Optional key normalizer. If not provided, a default will be used.</param>
    /// <returns>The decrypted data.</returns>
    public string DecryptBase64(
        string key,
        string encryptedValue,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = Convert.FromBase64String(encryptedValue);
        byte[] decryptedBytes = Decrypt(keyBytes, encryptedBytes, keyNormalizer);
        string result = Encoding.UTF8.GetString(decryptedBytes);
        return result;
    }

    protected byte[] EncryptBufferToStream(
        byte[] key,
        byte[] value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        keyNormalizer ??= CryptoHelper.DefaultKeyNormalizer;

        using MemoryStream keyStream = new MemoryStream(key, writable: false);
        using MemoryStream inputStream = new MemoryStream(value, writable: false);
        using MemoryStream outputStream = new MemoryStream();

        Encrypt(keyStream, inputStream, outputStream, keyNormalizer);
        byte[] result = outputStream.ToArray();

        return result;
    }

    protected byte[] DecryptBufferToStream(
        byte[] key,
        byte[] encryptedValue,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        keyNormalizer ??= CryptoHelper.DefaultKeyNormalizer;

        using MemoryStream keyStream = new MemoryStream(key, writable: false);
        using MemoryStream inputStream = new MemoryStream(encryptedValue, writable: false);
        using MemoryStream outputStream = new MemoryStream();

        Decrypt(keyStream, inputStream, outputStream, keyNormalizer);
        byte[] result = outputStream.ToArray();

        return result;
    }

    protected void EncryptStreamToBuffer(
        Stream key,
        Stream input,
        Stream output,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        using MemoryStream keyMs = new MemoryStream();
        key.CopyTo(keyMs);
        byte[] keyBytes = keyMs.ToArray();

        using MemoryStream inputMs = new MemoryStream();
        input.CopyTo(inputMs);
        byte[] inputBytes = inputMs.ToArray();

        byte[] encrypted = Encrypt(keyBytes, inputBytes, keyNormalizer);
        output.Write(encrypted, 0, encrypted.Length);
    }

    protected void DecryptStreamToBuffer(
        Stream key,
        Stream input,
        Stream output,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        using MemoryStream keyMs = new MemoryStream();
        key.CopyTo(keyMs);
        byte[] keyBytes = keyMs.ToArray();

        using MemoryStream inputMs = new MemoryStream();
        input.CopyTo(inputMs);
        byte[] inputBytes = inputMs.ToArray();

        byte[] decrypted = Decrypt(keyBytes, inputBytes, keyNormalizer);
        output.Write(decrypted, 0, decrypted.Length);
    }
}
