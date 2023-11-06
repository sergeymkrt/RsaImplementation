using System.Security.Cryptography;
using System.Text;

namespace RsaImplementation;

/// <summary>
/// Optimal Asymmetric Encryption Padding (OAEP) is a padding scheme for RSA encryption.
/// </summary>
public class OAEP
{
    private const string Label = "Xe7VRYNspp6sKKRz";

    public static byte[] Encode(byte[] plainText)
    {
        //1st step, assemble the message with the label and zeros
        var zeros = new byte[32];
        var labelBytes = Encoding.UTF8.GetBytes(Label);
        var labelPlaintextZeros = Concat(labelBytes, plainText, zeros);
        
        //2nd step, generate a random seed
        var randomBytes = GenerateRandomBytes(32); //32 bytes for SHA-256
        
        //3rd step, XOR Random String with Concatenated String
        var xorResult = XorByteArrays(randomBytes, labelPlaintextZeros);
        
        // calculate the hash of xorResult
        var hashOutput = Sha256(xorResult);

        //4rd step . Apply MGF to XOR result
        var mask = MGF1.Generate(xorResult, 32); // 32 bytes for SHA-256
        
        //5th step. XOR Mask with XOR result
        var xorMask = XorByteArrays(mask, randomBytes);
        
        // 6th step, Concatenate Result with hash output
        var finalPaddedMessage = Concat(xorMask, hashOutput);
        
        return finalPaddedMessage;
    }

    public static byte[] Decode(byte[] paddedText)
    {
        var maskLength = 32;
        var (xorMask, hashOutput) = SplitByteArray(paddedText, maskLength);
        
        var mask = MGF1.Generate(xorMask, maskLength); // 32 bytes for SHA-256
        
        var originalRandomBytes = XorByteArrays(mask, xorMask);
        
        var reconstructedConcatenatedString = ReconstructConcatenatedString(originalRandomBytes, Encoding.UTF8.GetBytes(Label), hashOutput.Length);
        
        var (label, plainText) = SplitByteArray(reconstructedConcatenatedString, Encoding.UTF8.GetBytes(Label).Length, hashOutput.Length);
        
        return plainText;
    }

    #region Private Methods

    private static byte[] Sha256(byte[] data)
    {
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(data);
    }
    
    private static byte[] Concat(params byte[][] arr)
    {
        var result = new byte[arr.Sum(a => a.Length)];
        var offset = 0;
        foreach (var data in arr)
        {
            Buffer.BlockCopy(data, 0, result, offset, data.Length);
            offset += data.Length;
        }
        return result;
    }
    
    private static (byte[] left, byte[] right) SplitByteArray(byte[] array, int rightLength) 
    {
        var leftLength = array.Length - rightLength;
        
        var left = new byte[leftLength];
        var right = new byte[rightLength];
        
        Buffer.BlockCopy(array, 0, left, 0, leftLength);
        Buffer.BlockCopy(array, leftLength, right, 0, rightLength);
        
        return (left, right);
    }
    
    private static (byte[] left, byte[] right) SplitByteArray(byte[] arr, int leftLength, int rightLength)
    {
        var left = new byte[leftLength];
        var right = new byte[rightLength];

        Buffer.BlockCopy(arr, 0, left, 0, leftLength);
        Buffer.BlockCopy(arr, leftLength, right, 0, rightLength);

        return (left, right);
    }
    

    private static byte[] GenerateRandomBytes(int length)
    {
        var randomBytes = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return randomBytes;
    }

    private static byte[] XorByteArrays(byte[] array1, byte[] array2)
    {
        var length = Math.Min(array1.Length, array2.Length);
        var result = new byte[length];
        
        for (var i = 0; i < length; i++)
        {
            result[i] = (byte) (array1[i] ^ array2[i]);
        }
        
        return result;
    }

    private static byte[] ReconstructConcatenatedString(byte[] originalRandomBytes, byte[] label, int plainTextLength)
    {
        // Determine if zeros are needed
        var zerosLength = Math.Max(32 - label.Length - plainTextLength, 0);

        // Create an array to hold the reconstructed concatenated string
        var concatenatedString = new byte[label.Length + plainTextLength + zerosLength];

        // Copy label to concatenated string
        Buffer.BlockCopy(label, 0, concatenatedString, 0, label.Length);

        // Copy original random bits to concatenated string
        Buffer.BlockCopy(originalRandomBytes, 0, concatenatedString, label.Length, originalRandomBytes.Length);

        // Append zeros to concatenated string (if needed)
        if (zerosLength > 0)
        {
            Buffer.BlockCopy(new byte[zerosLength], 0, concatenatedString, label.Length + originalRandomBytes.Length, zerosLength);
        }

        return concatenatedString;
    }

    #endregion
    
}