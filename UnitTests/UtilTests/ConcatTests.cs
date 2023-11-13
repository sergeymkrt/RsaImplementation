using EncryptionCore;

namespace UnitTests.UtilTests;

[TestFixture]
public class ConcatTests
{
    [Test]
    public void Concat_TwoArrays_ReturnsConcatenatedArray()
    {
        // Arrange
        byte[] array1 = { 0x01, 0x02, 0x03 };
        byte[] array2 = { 0x04, 0x05, 0x06 };

        // Act
        var result = OAEP.Concat(array1, array2);

        // Assert
        byte[] expected = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void Concat_MultipleArrays_ReturnsConcatenatedArray()
    {
        // Arrange
        byte[] array1 = { 0x01, 0x02 };
        byte[] array2 = { 0x03, 0x04, 0x05 };
        byte[] array3 = { 0x06, 0x07, 0x08 };

        // Act
        var result = OAEP.Concat(array1, array2, array3);

        // Assert
        byte[] expected = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
        Assert.That(result, Is.EqualTo(expected));
    }

    [Test]
    public void Concat_EmptyArrays_ReturnsEmptyArray()
    {
        // Arrange
        var result = OAEP.Concat();

        // Assert
        Assert.That(result, Is.Empty);
    }

    [Test]
    public void Concat_SingleArray_ReturnsSameArray()
    {
        // Arrange
        byte[] array = { 0x01, 0x02, 0x03 };

        // Act
        var result = OAEP.Concat(array);

        // Assert
        Assert.That(result, Is.EqualTo(array));
    }
}