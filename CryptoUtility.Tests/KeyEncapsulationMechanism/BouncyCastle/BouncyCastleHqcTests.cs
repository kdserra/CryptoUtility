using CryptoUtility.BouncyCastle;
using Org.BouncyCastle.Pqc.Crypto.Hqc;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleHqc128Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem => HqcImpl.Shared;
}

public sealed class BouncyCastleHqc192Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem { get; } = new HqcImpl(HqcParameters.hqc192);
}

public sealed class BouncyCastleHqc256Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem { get; } = new HqcImpl(HqcParameters.hqc256);
}
