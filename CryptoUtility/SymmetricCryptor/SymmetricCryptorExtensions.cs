using System.Security.Cryptography;
using System.Text;

namespace CryptoUtility;

public static class SymmetricCryptorExtensions
{
    private static readonly Pbkdf2KeyNormalizer s_DefaultKeyNormalizer = new Pbkdf2KeyNormalizer(
        HashAlgorithmName.SHA256,
        []
    );

    /// <summary>
    /// Generates a new cryptographic key for use in encryption or decryption operations.
    /// </summary>
    /// <returns>A byte array containing the generated cryptographic key.</returns>
    public static byte[] GenerateKey(this ISymmetricCryptor cryptor)
    {
        return RandomNumberGenerator.GetBytes(cryptor.KeySize);
    }

    public static IKeyNormalizer GetDefaultKeyNormalizer(this ISymmetricCryptor cryptor)
    {
        return s_DefaultKeyNormalizer;
    }

    #region UTF8
    public static string EncryptAsStringUtf8(
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

    public static byte[] EncryptAsBytesUtf8(
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

    public static string DecryptAsStringUtf8(
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

    public static byte[] DecryptAsBytesUtf8(
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
    #endregion

    #region UTF32
    public static string EncryptAsStringUtf32(
        this ISymmetricCryptor cryptor,
        string key,
        string value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] valueBytes = Encoding.UTF32.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = cryptor.Encrypt(keyBytes, valueBytes, keyNormalizer);
        string result = Convert.ToBase64String(encryptedBytes);
        return result;
    }

    public static byte[] EncryptAsBytesUtf32(
        this ISymmetricCryptor cryptor,
        string key,
        string value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] valueBytes = Encoding.UTF32.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] result = cryptor.Encrypt(keyBytes, valueBytes, keyNormalizer);
        return result;
    }

    public static string DecryptAsStringUtf32(
        this ISymmetricCryptor cryptor,
        string key,
        string encryptedValue,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = Convert.FromBase64String(encryptedValue);
        byte[] decryptedBytes = cryptor.Decrypt(keyBytes, encryptedBytes, keyNormalizer);
        string result = Encoding.UTF32.GetString(decryptedBytes);
        return result;
    }

    public static byte[] DecryptAsBytesUtf32(
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
    #endregion

    #region ASCII
    public static string EncryptAsStringAscii(
        this ISymmetricCryptor cryptor,
        string key,
        string value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] valueBytes = Encoding.ASCII.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = cryptor.Encrypt(keyBytes, valueBytes, keyNormalizer);
        string result = Convert.ToBase64String(encryptedBytes);
        return result;
    }

    public static byte[] EncryptAsBytesAscii(
        this ISymmetricCryptor cryptor,
        string key,
        string value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] valueBytes = Encoding.ASCII.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] result = cryptor.Encrypt(keyBytes, valueBytes, keyNormalizer);
        return result;
    }

    public static string DecryptAsStringAscii(
        this ISymmetricCryptor cryptor,
        string key,
        string encryptedValue,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = Convert.FromBase64String(encryptedValue);
        byte[] decryptedBytes = cryptor.Decrypt(keyBytes, encryptedBytes, keyNormalizer);
        string result = Encoding.ASCII.GetString(decryptedBytes);
        return result;
    }

    public static byte[] DecryptAsBytesAscii(
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
    #endregion

    #region Unicode (UTF-16 LE)
    public static string EncryptAsStringUnicode(
        this ISymmetricCryptor cryptor,
        string key,
        string value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] valueBytes = Encoding.Unicode.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = cryptor.Encrypt(keyBytes, valueBytes, keyNormalizer);
        string result = Convert.ToBase64String(encryptedBytes);
        return result;
    }

    public static byte[] EncryptAsBytesUnicode(
        this ISymmetricCryptor cryptor,
        string key,
        string value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] valueBytes = Encoding.Unicode.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] result = cryptor.Encrypt(keyBytes, valueBytes, keyNormalizer);
        return result;
    }

    public static string DecryptAsStringUnicode(
        this ISymmetricCryptor cryptor,
        string key,
        string encryptedValue,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = Convert.FromBase64String(encryptedValue);
        byte[] decryptedBytes = cryptor.Decrypt(keyBytes, encryptedBytes, keyNormalizer);
        string result = Encoding.Unicode.GetString(decryptedBytes);
        return result;
    }

    public static byte[] DecryptAsBytesUnicode(
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
    #endregion

    #region BigEndianUnicode (UTF-16 BE)
    public static string EncryptAsStringBigEndianUnicode(
        this ISymmetricCryptor cryptor,
        string key,
        string value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] valueBytes = Encoding.BigEndianUnicode.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = cryptor.Encrypt(keyBytes, valueBytes, keyNormalizer);
        string result = Convert.ToBase64String(encryptedBytes);
        return result;
    }

    public static byte[] EncryptAsBytesBigEndianUnicode(
        this ISymmetricCryptor cryptor,
        string key,
        string value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] valueBytes = Encoding.BigEndianUnicode.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] result = cryptor.Encrypt(keyBytes, valueBytes, keyNormalizer);
        return result;
    }

    public static string DecryptAsStringBigEndianUnicode(
        this ISymmetricCryptor cryptor,
        string key,
        string encryptedValue,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = Convert.FromBase64String(encryptedValue);
        byte[] decryptedBytes = cryptor.Decrypt(keyBytes, encryptedBytes, keyNormalizer);
        string result = Encoding.BigEndianUnicode.GetString(decryptedBytes);
        return result;
    }

    public static byte[] DecryptAsBytesBigEndianUnicode(
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
    #endregion

    #region Latin1 (ISO-8859-1)
    public static string EncryptAsStringLatin1(
        this ISymmetricCryptor cryptor,
        string key,
        string value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] valueBytes = Encoding.Latin1.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = cryptor.Encrypt(keyBytes, valueBytes, keyNormalizer);
        string result = Convert.ToBase64String(encryptedBytes);
        return result;
    }

    public static byte[] EncryptAsBytesLatin1(
        this ISymmetricCryptor cryptor,
        string key,
        string value,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] valueBytes = Encoding.Latin1.GetBytes(value);
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] result = cryptor.Encrypt(keyBytes, valueBytes, keyNormalizer);
        return result;
    }

    public static string DecryptAsStringLatin1(
        this ISymmetricCryptor cryptor,
        string key,
        string encryptedValue,
        IKeyNormalizer? keyNormalizer = null
    )
    {
        byte[] keyBytes = Encoding.UTF8.GetBytes(key);
        byte[] encryptedBytes = Convert.FromBase64String(encryptedValue);
        byte[] decryptedBytes = cryptor.Decrypt(keyBytes, encryptedBytes, keyNormalizer);
        string result = Encoding.Latin1.GetString(decryptedBytes);
        return result;
    }

    public static byte[] DecryptAsBytesLatin1(
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
    #endregion

    #region Base64
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

    public static string GenerateKeyAsStringBase64(this ISymmetricCryptor cryptor)
    {
        byte[] key = cryptor.GenerateKey();
        string result = Convert.ToBase64String(key);

        return result;
    }

    public static byte[] GenerateKeyAsBytesBase64Utf8(this ISymmetricCryptor cryptor)
    {
        byte[] key = cryptor.GenerateKey();
        string base64String = Convert.ToBase64String(key);
        byte[] result = Encoding.UTF8.GetBytes(base64String);
        return result;
    }
    #endregion
}
