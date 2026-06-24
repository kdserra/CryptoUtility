using CryptoUtility.BouncyCastle;
using Org.BouncyCastle.Pqc.Crypto.Bike;

namespace CryptoUtility.Tests;

public sealed class BouncyCastleBike128Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem => BikeImpl.Shared;
}

public sealed class BouncyCastleBike192Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem { get; } = new BikeImpl(BikeParameters.bike192);
}

public sealed class BouncyCastleBike256Tests : KeyEncapsulationMechanismTests
{
    internal override IKeyEncapsulationMechanism Kem { get; } = new BikeImpl(BikeParameters.bike256);
}
