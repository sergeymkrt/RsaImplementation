using System.Text;
using EncryptionCore;

namespace UnitTests;

[TestFixture]
public class Mgf1Tests
{
    [Test]
    public void TestMgf1Generation()
    {
        // Arrange
        var seed = "TestSeed"u8.ToArray();
        const int maskLen = 32; // SHA-256 output length

        // Act
        var result = MGF1.Generate(seed, maskLen);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Length, Is.EqualTo(maskLen));
    }

    [Test]
    public void TestMgf1WithZeroMaskLength()
    {
        // Arrange
        var seed = "AnotherSeed"u8.ToArray();
        const int maskLen = 0;

        // Act
        var result = MGF1.Generate(seed, maskLen);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Length, Is.EqualTo(0));
    }

    [Test]
    public void TestMgf1WithDifferentSeed()
    {
        // Arrange
        var seed1 = "Seed1"u8.ToArray();
        var seed2 = "Seed2"u8.ToArray();
        const int maskLen = 16;

        // Act
        var result1 = MGF1.Generate(seed1, maskLen);
        var result2 = MGF1.Generate(seed2, maskLen);

        // Assert
        Assert.That(result1, Is.Not.Null);
        Assert.That(result2, Is.Not.Null);
        Assert.That(result2, Is.Not.EqualTo(result1));
    }

    [Test]
    public void TestMgf1WithShortMaskLength()
    {
        // Arrange
        var seed = "ShortMaskLength"u8.ToArray();
        const int maskLen = 8;

        // Act
        var result = MGF1.Generate(seed, maskLen);

        // Assert
        Assert.That(result, Is.Not.Null);
        Assert.That(result.Length, Is.EqualTo(maskLen));
    }

}