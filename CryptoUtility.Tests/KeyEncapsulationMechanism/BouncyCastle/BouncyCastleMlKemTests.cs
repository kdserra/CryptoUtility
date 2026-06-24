using CryptoUtility.BouncyCastle;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleMlKem768Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem => MlKem768Impl.Shared;
}

public sealed class BouncyCastleMlKem1024Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem => MlKem1024Impl.Shared;
}
