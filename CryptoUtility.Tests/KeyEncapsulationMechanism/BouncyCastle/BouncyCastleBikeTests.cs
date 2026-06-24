using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleBike128Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem => Bike128Impl.Shared;
}

public sealed class BouncyCastleBike192Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem => Bike192Impl.Shared;
}

public sealed class BouncyCastleBike256Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem => Bike256Impl.Shared;
}
