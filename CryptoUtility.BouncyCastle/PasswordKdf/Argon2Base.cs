using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Base class for Bouncy Castle Argon2 implementations.
/// </summary>
public abstract class Argon2Base : IPasswordKdf, IPasswordHasher
{
    private readonly int _type;
    private readonly int _defaultIterations;
    private readonly int _defaultMemoryKb;
    private readonly int _defaultParallelism;
    private readonly int _defaultSaltLength;
    private readonly int _defaultOutputLength;

    /// <summary>
    /// Initializes a new instance of the <see cref="Argon2Base"/> class.
    /// </summary>
    protected Argon2Base(
        int type,
        int defaultIterations,
        int defaultMemoryKb,
        int defaultParallelism,
        int defaultSaltLength,
        int defaultOutputLength
    )
    {
        _type = type;
        _defaultIterations = defaultIterations;
        _defaultMemoryKb = defaultMemoryKb;
        _defaultParallelism = defaultParallelism;
        _defaultSaltLength = defaultSaltLength;
        _defaultOutputLength = defaultOutputLength;
    }

    private string TypeString
    {
        get
        {
            if (_type == Argon2Parameters.Argon2d)
                return "argon2d";
            if (_type == Argon2Parameters.Argon2i)
                return "argon2i";
            if (_type == Argon2Parameters.Argon2id)
                return "argon2id";
            throw new InvalidOperationException();
        }
    }

    /// <inheritdoc />
    public byte[] DeriveKey(string passwordUtf8, byte[] salt, int outputLength)
    {
        return DeriveKey(
            passwordUtf8,
            salt,
            _defaultIterations,
            _defaultMemoryKb,
            _defaultParallelism,
            outputLength
        );
    }

    /// <summary>
    /// Derives a key using custom Argon2 parameters.
    /// </summary>
    public byte[] DeriveKey(
        string password,
        byte[] salt,
        int iterations,
        int memoryKb,
        int parallelism,
        int outputLength
    )
    {
        LibraryHelper.ThrowIfAnyNull(password, salt);
        if (iterations <= 0)
            throw new ArgumentOutOfRangeException(nameof(iterations));
        if (memoryKb <= 0)
            throw new ArgumentOutOfRangeException(nameof(memoryKb));
        if (parallelism <= 0)
            throw new ArgumentOutOfRangeException(nameof(parallelism));
        if (outputLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(outputLength));

        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        try
        {
            var paramBuilder = new Argon2Parameters.Builder(_type)
                .WithIterations(iterations)
                .WithMemoryAsKB(memoryKb)
                .WithParallelism(parallelism)
                .WithSalt(salt);

            var generator = new Argon2BytesGenerator();
            generator.Init(paramBuilder.Build());

            byte[] result = new byte[outputLength];
            generator.GenerateBytes(passwordBytes, result, 0, result.Length);
            return result;
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
            _defaultIterations,
            _defaultMemoryKb,
            _defaultParallelism,
            _defaultOutputLength
        );

        string saltB64 = PhcB64.ToB64String(salt);
        string hashB64 = PhcB64.ToB64String(hash);

        return $"${TypeString}$v=19$m={_defaultMemoryKb},t={_defaultIterations},p={_defaultParallelism}${saltB64}${hashB64}";
    }

    /// <inheritdoc />
    public bool VerifyPassword(string password, string hashedPasswordString)
    {
        LibraryHelper.ThrowIfAnyNull(password, hashedPasswordString);
        try
        {
            var parts = hashedPasswordString.Split('$');
            if (parts.Length != 6 || parts[1] != TypeString)
            {
                return false;
            }

            if (parts[2] != "v=19")
                return false;

            int memoryKb = _defaultMemoryKb;
            int iterations = _defaultIterations;
            int parallelism = _defaultParallelism;

            foreach (var kv in parts[3].Split(','))
            {
                var kvParts = kv.Split('=');
                if (kvParts.Length != 2)
                    return false;
                var key = kvParts[0].Trim();
                var val = kvParts[1].Trim();

                if (key == "m")
                {
                    memoryKb = int.Parse(val);
                }
                else if (key == "t")
                {
                    iterations = int.Parse(val);
                }
                else if (key == "p")
                {
                    parallelism = int.Parse(val);
                }
            }

            var saltB64 = parts[4];
            byte[] salt = PhcB64.FromB64String(saltB64);

            var hashB64 = parts[5];
            byte[] expectedHash = PhcB64.FromB64String(hashB64);

            byte[] computedHash = DeriveKey(
                password,
                salt,
                iterations,
                memoryKb,
                parallelism,
                expectedHash.Length
            );
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
