using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Argon2d Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Argon2dImpl : Argon2Base
{
    /// <summary>
    /// Shared static instance of <see cref="Argon2dImpl"/>.
    /// </summary>
    public static readonly Argon2dImpl Shared = new();

    private Argon2dImpl()
        : base(
            Argon2Parameters.Argon2d,
            defaultIterations: 3,
            defaultMemoryKb: 65536,
            defaultParallelism: 4,
            defaultSaltLength: 16,
            defaultOutputLength: 32
        ) { }
}
