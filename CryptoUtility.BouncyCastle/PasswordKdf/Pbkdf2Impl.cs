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
        LibraryHelper.ThrowIfAnyNull(password, salt);
        if (iterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(iterations));
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLength));

        var gen = new Pkcs5S2ParametersGenerator(new Sha256Digest());
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        gen.Init(passwordBytes, salt, iterations);
        var keyParam = (KeyParameter)gen.GenerateDerivedMacParameters(outputLength * 8);

        CryptographicOperations.ZeroMemory(passwordBytes);

        return keyParam.GetKey();
    }

    /// <inheritdoc />
    public string HashPassword(string password)
    {
        LibraryHelper.ThrowIfAnyNull(password);
        byte[] salt = CryptoHelper.GetBytes(_defaultSaltLength);
        byte[] hash = DeriveKey(password, salt, _defaultIterations, _defaultOutputLength);

        string saltB64 = Convert.ToBase64String(salt).TrimEnd('=');
        string hashB64 = Convert.ToBase64String(hash).TrimEnd('=');

        return $"$pbkdf2-sha256$i={_defaultIterations}${saltB64}${hashB64}";
    }

    /// <inheritdoc />
    public bool VerifyPassword(string password, string hashedPasswordString)
    {
        LibraryHelper.ThrowIfAnyNull(password, hashedPasswordString);
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
            int saltPadding = (4 - (saltB64.Length % 4)) % 4;
            byte[] salt = Convert.FromBase64String(saltB64 + new string('=', saltPadding));

            var hashB64 = parts[4];
            int hashPadding = (4 - (hashB64.Length % 4)) % 4;
            byte[] expectedHash = Convert.FromBase64String(hashB64 + new string('=', hashPadding));

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
