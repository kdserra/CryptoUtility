using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.BouncyCastle;

/// <summary>
/// Bouncy Castle Argon2id Implementation.
/// </summary>
[GenerateStaticApi]
public sealed class Argon2idImpl : Argon2Base
{
    /// <summary>
    /// Shared static instance of <see cref="Argon2idImpl"/>.
    /// </summary>
    public static readonly Argon2idImpl Shared = new();

    private Argon2idImpl()
        : base(
            Argon2Parameters.Argon2id,
            defaultIterations: 3,
            defaultMemoryKb: 65536,
            defaultParallelism: 4,
            defaultSaltLength: 16,
            defaultOutputLength: 32
        ) { }
}
