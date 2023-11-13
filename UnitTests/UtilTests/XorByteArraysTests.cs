using EncryptionCore;

namespace UnitTests.UtilTests;

[TestFixture]
public class XorByteArraysTests
{
    [Test]
    public void XorByteArrays_SameLengthArrays_ReturnsXorResult()
    {
        // Arrange
        byte[] array1 = { 0x01, 0x02, 0x03 };
        byte[] array2 = { 0x04, 0x05, 0x06 };

        // Act
        var result = OAEP.XorByteArrays(array1, array2);

        // Assert
        byte[] expected = { 0x05, 0x07, 0x05 };
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void XorByteArrays_Array2Shorter_ReturnsXorResult()
    {
        // Arrange
        byte[] array1 = { 0x01, 0x02, 0x03, 0x04 };
        byte[] array2 = { 0x05, 0x06 };

        // Act
        var result = OAEP.XorByteArrays(array1, array2);

        // Assert
        byte[] expected = { 0x04, 0x04 };
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void XorByteArrays_Array1Shorter_ReturnsXorResult()
    {
        // Arrange
        byte[] array1 = { 0x01, 0x02 };
        byte[] array2 = { 0x03, 0x04, 0x05, 0x06 };

        // Act
        var result = OAEP.XorByteArrays(array1, array2);

        // Assert
        byte[] expected = { 0x02, 0x06 };
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void XorByteArrays_EmptyArrays_ReturnsEmptyArray()
    {
        // Arrange
        var array1 = Array.Empty<byte>();
        var array2 = Array.Empty<byte>();

        // Act
        var result = OAEP.XorByteArrays(array1, array2);

        // Assert
        Assert.That(result, Is.Empty);
    }
}