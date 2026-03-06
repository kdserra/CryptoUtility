using System.Text;
#if NET8_0_OR_GREATER
using System.Security.Cryptography;
#endif

namespace CryptoUtility;

public static class SymmetricCryptorExtensions
{
    private static readonly Pbkdf2KeyNormalizer s_DefaultKeyNormalizer = new Pbkdf2KeyNormalizer(
#if NET8_0_OR_GREATER
        hashAlgorithm: HashAlgorithmName.SHA256,
#endif
        salt: []
    );

    /// <summary>
    /// Generates a new cryptographic key for use in encryption or decryption operations.
    /// </summary>
    /// <returns>A byte array containing the generated cryptographic key.</returns>
    public static byte[] GenerateKey(this ISymmetricCryptor cryptor)
    {
        return CryptoHelper.GetBytes(cryptor.KeySize);
    }

    public static IKeyNormalizer GetDefaultKeyNormalizer(this ISymmetricCryptor cryptor)
    {
        return s_DefaultKeyNormalizer;
    }

    /// <summary>
    /// Encrypts the specified value using the provided key and returns the encrypted data.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <param name="key">The cryptographic key used for encryption.</param>
    /// <param name="value">The value to encrypt.</param>
    /// <param name="keyNormalizer">Optional key normalizer. If not provided, a default will be used.</param>
    /// <returns>The encrypted data.</returns>
    public static string EncryptAsStringBase64(
        this ISymmetricCryptor cryptor,
        string key,
        string value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] valueBytes = Encoding.UTF8.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = cryptor.Encrypt(keyBytes, valueBytes, keyNormalizer);
        string result = Convert.ToBase64String(encryptedBytes);
        return result;
    }

    /// <summary>
    /// Encrypts the specified value using the provided key and returns the encrypted data.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <param name="key">The cryptographic key used for encryption.</param>
    /// <param name="value">The value to encrypt.</param>
    /// <param name="keyNormalizer">Optional key normalizer. If not provided, a default will be used.</param>
    /// <returns>The encrypted data.</returns>
    public static byte[] EncryptAsBytesBase64(
        this ISymmetricCryptor cryptor,
        string key,
        string value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] valueBytes = Encoding.UTF8.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] result = cryptor.Encrypt(keyBytes, valueBytes, keyNormalizer);
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
    public static string DecryptAsStringBase64(
        this ISymmetricCryptor cryptor,
        string key,
        string encryptedValue,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = Convert.FromBase64String(encryptedValue);
        byte[] decryptedBytes = cryptor.Decrypt(keyBytes, encryptedBytes, keyNormalizer);
        string result = Encoding.UTF8.GetString(decryptedBytes);
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
    public static byte[] DecryptAsBytesBase64(
        this ISymmetricCryptor cryptor,
        string key,
        byte[] encryptedValue,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] result = cryptor.Decrypt(keyBytes, encryptedValue, keyNormalizer);
        return result;
    }

    /// <summary>
    /// Generates a new cryptographic key and returns it as a Base64 encoded string.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <returns>The generated key as a Base64 string.</returns>
    public static string GenerateKeyAsStringBase64(this ISymmetricCryptor cryptor)
    {
        byte[] key = cryptor.GenerateKey();
        string result = Convert.ToBase64String(key);
        return result;
    }

    /// <summary>
    /// Generates a new cryptographic key, encodes it as Base64, and returns the UTF-8 bytes of that string.
    /// </summary>
    /// <param name="cryptor">The symmetric cryptor instance.</param>
    /// <returns>The generated key as UTF-8 encoded Base64 bytes.</returns>
    public static byte[] GenerateKeyAsBytesBase64Utf8(this ISymmetricCryptor cryptor)
    {
        byte[] key = cryptor.GenerateKey();
        string base64String = Convert.ToBase64String(key);
        byte[] result = Encoding.UTF8.GetBytes(base64String);
        return result;
    }
}
