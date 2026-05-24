using System.Security.Cryptography;

namespace CryptoUtility;

/// <summary>
/// HKDF.NET implementation of HKDF.
/// https://github.com/samuel-lucas6/HKDF.NET
/// </summary>
[GenerateStaticApi]
public class HkdfDotNetImpl : IKeyExpansionKdf
{
    public static readonly HkdfDotNetImpl Shared = new();

    private static readonly HashAlgorithmName DefaultHashAlgorithm = HashAlgorithmName.SHA256;

    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info
    )
    {
        return DeriveKey(DefaultHashAlgorithm, inputKeyMaterial, outputLength, info, salt);
    }

    public byte[] DeriveKey(
        byte[] inputKeyMaterial,
        int iterations,
        int outputLength,
        byte[] salt,
        byte[] info,
        HashAlgorithmName hashAlgorithm
    )
    {
        return DeriveKey(hashAlgorithm, inputKeyMaterial, outputLength, info, salt);
    }

    private static byte[] DeriveKey(
        HashAlgorithmName hashAlgorithmName,
        byte[] inputKeyingMaterial,
        int outputLength,
        byte[] info,
        byte[]? salt = null
    )
    {
        byte[] key = Extract(hashAlgorithmName, inputKeyingMaterial, salt);
        return Expand(hashAlgorithmName, key, outputLength, info);
    }

    private static byte[] Extract(
        HashAlgorithmName hashAlgorithmName,
        byte[] inputKeyingMaterial,
        byte[]? salt = null
    )
    {
        if (salt == null)
        {
            salt = Array.Empty<byte>();
        }
        using (var hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, salt))
        {
            hmac.AppendData(inputKeyingMaterial);
            return hmac.GetHashAndReset();
        }
    }

    private static byte[] Expand(
        HashAlgorithmName hashAlgorithmName,
        byte[] key,
        int outputLength,
        byte[] info
    )
    {
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key), "The key cannot be null.");
        }
        if (info == null)
        {
            info = Array.Empty<byte>();
        }
        int hashLength = GetHashLength(hashAlgorithmName);
        if (hashLength == 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(hashAlgorithmName),
                "Please specify a SHA2 algorithm."
            );
        }
        if (outputLength == 0 || outputLength > 255 * hashLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(outputLength),
                outputLength,
                $"The output length must be greater than 0 and less than 255 * {hashLength}."
            );
        }
        int iterations = (outputLength + hashLength - 1) / hashLength;
        var counter = new byte[1];
        var previousHash = Array.Empty<byte>();
        var outputKeyingMaterial = new byte[outputLength];
        int bytesWritten = 0;
        using (var hmac = IncrementalHash.CreateHMAC(hashAlgorithmName, key))
        {
            for (int i = 1; i <= iterations; i++)
            {
                counter[0] = (byte)i;
                hmac.AppendData(previousHash);
                hmac.AppendData(info);
                hmac.AppendData(counter);
                previousHash = hmac.GetHashAndReset();
                Array.Copy(
                    previousHash,
                    sourceIndex: 0,
                    outputKeyingMaterial,
                    bytesWritten,
                    i != iterations ? previousHash.Length : outputLength - bytesWritten
                );
                bytesWritten += hashLength;
            }
        }
        return outputKeyingMaterial;
    }

    private static int GetHashLength(HashAlgorithmName hashAlgorithmName)
    {
        if (hashAlgorithmName == HashAlgorithmName.SHA256)
        {
            return 32;
        }
        if (hashAlgorithmName == HashAlgorithmName.SHA384)
        {
            return 48;
        }
        return hashAlgorithmName == HashAlgorithmName.SHA512 ? 64 : 0;
    }
}
