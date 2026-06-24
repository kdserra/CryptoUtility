using CryptoUtility.BouncyCastle;
using Org.BouncyCastle.Crypto.Parameters;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleMlKem768Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem => MlKemImpl.Shared;
}

public sealed class BouncyCastleMlKem1024Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem { get; } = new MlKemImpl(MLKemParameters.ml_kem_1024);
}
