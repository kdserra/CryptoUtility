using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Scrypt Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class ScryptImpl : IPasswordKdf, IPasswordHasher
{
    /// <summary>
    /// Shared static instance of <see cref="ScryptImpl"/>.
    /// </summary>
    public static readonly ScryptImpl Shared = new();

    private readonly int _defaultN; // Cost parameter (e.g. 16384)
    private readonly int _defaultR; // Block size (e.g. 8)
    private readonly int _defaultP; // Parallelization (e.g. 1)
    private readonly int _defaultSaltLength;
    private readonly int _defaultOutputLength;

    /// <summary>
    /// Initializes a new instance of the <see cref="ScryptImpl"/> class with secure defaults.
    /// </summary>
    public ScryptImpl()
        : this(16384, 8, 1, 16, 32) { }

    /// <summary>
    /// Initializes a new instance of the <see cref="ScryptImpl"/> class with custom default parameters.
    /// </summary>
    public ScryptImpl(
        int defaultN,
        int defaultR,
        int defaultP,
        int defaultSaltLength,
        int defaultOutputLength
    )
    {
        _defaultN = defaultN;
        _defaultR = defaultR;
        _defaultP = defaultP;
        _defaultSaltLength = defaultSaltLength;
        _defaultOutputLength = defaultOutputLength;
    }

    /// <inheritdoc />
    public byte[] DeriveKey(string passwordUtf8, byte[] salt, int outputLength)
    {
        return DeriveKey(passwordUtf8, salt, _defaultN, _defaultR, _defaultP, outputLength);
    }

    /// <summary>
    /// Derives a key of the specified length from the password, salt, and Scrypt parameters.
    /// </summary>
    public byte[] DeriveKey(string password, byte[] salt, int N, int r, int p, int outputLength)
    {
        LibraryHelper.ThrowIfAnyNull(password, salt);
        if (N <= 1 || (N & (N - 1)) != 0)
            throw new ArgumentException("N must be a power of 2 greater than 1.", nameof(N));
        if (r <= 0)
            throw new ArgumentOutOfRangeException(nameof(r));
        if (p <= 0)
            throw new ArgumentOutOfRangeException(nameof(p));
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLength));

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            return SCrypt.Generate(passwordBytes, salt, N, r, p, outputLength);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    /// <inheritdoc />
    public string HashPassword(string password)
    {
        LibraryHelper.ThrowIfAnyNull(password);
        byte[] salt = CryptoHelper.GetBytes(_defaultSaltLength);
        byte[] hash = DeriveKey(
            password,
            salt,
            _defaultN,
            _defaultR,
            _defaultP,
            _defaultOutputLength
        );

        int ln = (int)Math.Round(Math.Log(_defaultN, 2));

        string saltB64 = PhcB64.ToB64String(salt);
        string hashB64 = PhcB64.ToB64String(hash);

        return $"$scrypt$ln={ln},r={_defaultR},p={_defaultP}${saltB64}${hashB64}";
    }

    /// <inheritdoc />
    public bool VerifyPassword(string password, string hashedPasswordString)
    {
        LibraryHelper.ThrowIfAnyNull(password, hashedPasswordString);
        try
        {
            var parts = hashedPasswordString.Split('$');
            if (parts.Length != 5 || parts[1] != "scrypt")
            {
                return false;
            }

            var paramsPart = parts[2];
            int n = 16384;
            int r = 8;
            int p = 1;

            foreach (var kv in paramsPart.Split(','))
            {
                var kvParts = kv.Split('=');
                if (kvParts.Length != 2)
                    return false;
                var key = kvParts[0].Trim();
                var val = kvParts[1].Trim();

                if (key == "ln")
                {
                    int ln = int.Parse(val);
                    n = (int)Math.Pow(2, ln);
                }
                else if (key == "r")
                {
                    r = int.Parse(val);
                }
                else if (key == "p")
                {
                    p = int.Parse(val);
                }
            }

            var saltB64 = parts[3];
            byte[] salt = PhcB64.FromB64String(saltB64);

            var hashB64 = parts[4];
            byte[] expectedHash = PhcB64.FromB64String(hashB64);

            byte[] computedHash = DeriveKey(password, salt, n, r, p, expectedHash.Length);
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
