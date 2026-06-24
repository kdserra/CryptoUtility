using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle PBKDF2 Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Pbkdf2Impl : IPasswordKdf, IPasswordHasher
{
    /// <summary>
    /// Shared static instance of <see cref="Pbkdf2Impl"/>.
    /// </summary>
    public static readonly Pbkdf2Impl Shared = new();

    private readonly int _defaultIterations;
    private readonly int _defaultSaltLength;
    private readonly int _defaultOutputLength;

    /// <summary>
    /// Initializes a new instance of the <see cref="Pbkdf2Impl"/> class with secure defaults.
    /// </summary>
    public Pbkdf2Impl()
        : this(600000, 16, 32) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="Pbkdf2Impl"/> class with custom default parameters.
    /// </summary>
    public Pbkdf2Impl(int defaultIterations, int defaultSaltLength, int defaultOutputLength)
    {
        _defaultIterations = defaultIterations;
        _defaultSaltLength = defaultSaltLength;
        _defaultOutputLength = defaultOutputLength;
    }

    /// <inheritdoc />
    public byte[] DeriveKey(string passwordUtf8, byte[] salt, int outputLength)
    {
        return DeriveKey(passwordUtf8, salt, _defaultIterations, outputLength);
    }

    /// <summary>
    /// Derives a key of the specified length from the password, salt, and iterations.
    /// </summary>
    public byte[] DeriveKey(string password, byte[] salt, int iterations, int outputLength)
    {
        LibraryHelper.ThrowIfNull(password);
        LibraryHelper.ThrowIfNull(salt);
        if (iterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(iterations));
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLength));

        KeyParameter keyParam;
        byte[] passwordBytes = Array.Empty<byte>();

        try
        {
            var gen = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            passwordBytes = Encoding.UTF8.GetBytes(password);
            gen.Init(passwordBytes, salt, iterations);
            keyParam = (KeyParameter)gen.GenerateDerivedMacParameters(outputLength * 8);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }

        return keyParam.GetKey();
    }

    /// <inheritdoc />
    public string HashPassword(string password)
    {
        LibraryHelper.ThrowIfNull(password);
        byte[] salt = CryptoHelper.GetBytes(_defaultSaltLength);
        byte[] hash = DeriveKey(password, salt, _defaultIterations, _defaultOutputLength);

        string saltB64 = PhcB64.ToB64String(salt);
        string hashB64 = PhcB64.ToB64String(hash);

        return $"$pbkdf2-sha256$i={_defaultIterations}${saltB64}${hashB64}";
    }

    /// <inheritdoc />
    public bool VerifyPassword(string password, string hashedPasswordString)
    {
        LibraryHelper.ThrowIfNull(password);
        LibraryHelper.ThrowIfNull(hashedPasswordString);
        try
        {
            var parts = hashedPasswordString.Split('$');
            if (parts.Length != 5 || parts[1] != "pbkdf2-sha256")
            {
                return false;
            }

            var paramsPart = parts[2];
            if (!paramsPart.StartsWith("i="))
                return false;
            int iterations = int.Parse(paramsPart.Substring(2));

            var saltB64 = parts[3];
            byte[] salt = PhcB64.FromB64String(saltB64);

            var hashB64 = parts[4];
            byte[] expectedHash = PhcB64.FromB64String(hashB64);

            byte[] computedHash = DeriveKey(password, salt, iterations, expectedHash.Length);
            try
            {
                return CryptographicOperations.FixedTimeEquals(computedHash, expectedHash);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(computedHash);
            }
        }
        catch
        {
            return false;
        }
    }
}
