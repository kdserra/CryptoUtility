using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Argon2i Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Argon2iImpl : Argon2Base
{
    /// <summary>
    /// Shared static instance of <see cref="Argon2iImpl"/>.
    /// </summary>
    public static readonly Argon2iImpl Shared = new();

    private Argon2iImpl() : base(Argon2Parameters.Argon2i, defaultIterations: 3, defaultMemoryKb: 65536, defaultParallelism: 4, defaultSaltLength: 16, defaultOutputLength: 32)
    {
    }
}
