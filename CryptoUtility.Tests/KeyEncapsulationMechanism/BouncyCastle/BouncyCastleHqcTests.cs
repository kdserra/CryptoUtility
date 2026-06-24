using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleHqc128Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem => Hqc128Impl.Shared;
}

public sealed class BouncyCastleHqc192Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem => Hqc192Impl.Shared;
}

public sealed class BouncyCastleHqc256Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem => Hqc256Impl.Shared;
}
