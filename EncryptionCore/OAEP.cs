using System.Security.Cryptography;
using System.Text;

namespace EncryptionCore;

/// <summary>
/// Optimal Asymmetric Encryption Padding (OAEP) is a padding scheme for RSA encryption.
/// </summary>
public static class OAEP
{
    private const string Label = "Xe7VRYNspp6sKKRz";

    public static byte[] Encode(byte[] plainText, int keysize = 2048)
    {
        // k is the length of the RSA modulus n in bytes
        // hLen is the length of the output of the hash function in bytes,
        // mLen is the length of the message to be encrypted in bytes
        // M is the message to be padded (at most k - 2 * hLen - 2 bytes)
        var k = keysize / 8; // 256 bits
        var mLen = plainText.Length;

        //1. Hash the label L using the chosen hash function: lHash = Hash(L)
        var lhash = Sha256(Encoding.UTF8.GetBytes(Label));
        var hLen = lhash.Length;

        //check if M is valid
        if (mLen > k - 2 * hLen - 2)
        {
            throw new ArgumentException("Message too long");
        }

        //2. Generate a padding string PS consisting of k - mLen - 2 * hLen - 2 bytes with the value 0x00.
        var ps = new byte[k - mLen - 2 * hLen - 2];

        //3. Concatenate lHash, PS, the single byte 0x01, and the message M to form a data block DB: DB=lHash||PS||-x-1||M
        // This data block has length k - hLen - 1 bytes
        var db = Concat(lhash, ps, [0x01], plainText);

        //4. Generate a random seed of length hLen.
        var seed = GenerateRandomBytes(hLen);

        //5.Use the mask generating function to generate a mask of the appropriate length for the data block
        // dbMask = MGF(seed, k - hLen - 1)
        var dbMask = MGF1.Generate(seed, k - hLen - 1);

        //6.Mask the data block with the generated Mask. maskedDB = DB XOR dbMask
        var maskedDb = XorByteArrays(db, dbMask);

        //7.Use the mask generating function to generate a mask of length hLen for the seed: seedMask = MGF(maskedDB, hLen)
        var seedMask = MGF1.Generate(maskedDb, hLen);
        //8.Mask the seed with the generated mask : maskedSeed = seed XOR seedMask
        var maskedSeed = XorByteArrays(seed, seedMask);

        //9.the encoded (padded) message is the byte 0x00 concatenated with the maskedSeed and maskedDB EM=0x00||maskedSeed||maskedDB
        var em = Concat([0x00], maskedSeed, maskedDb);

        return em;
    }

    public static byte[] Decode(byte[] paddedText, int keysize = 2048)
    {
        var k = keysize / 8;

        //1. Hash the label L using the chosen hash function: lHash = Hash(L)
        var lhash = Sha256(Encoding.UTF8.GetBytes(Label));
        var hLen = lhash.Length;

        //2. To reverse  Step 9, split the encoded message EM into the byte 0x00, the maskedSeed(with length hLen) and the maskedDB: EM = 0x00 || maskedSeed||maskedDB
        var (firstByte, maskedSeed, maskedDB) = SplitEncodedMessage(paddedText, hLen);

        //3. Generate seedMask which was used to mask the seed: seedMask = MGF(maskedDB, hLen)
        var seedMask = MGF1.Generate(maskedDB, hLen);

        //4. To reverse step 8. recover the seed with the seedMask: seed = maskedSeed XOR seedMask
        var seed = XorByteArrays(maskedSeed, seedMask);

        //5. Generate the dbMask which was used to mask the data block: dbMask = MGF(seed, k-hLen-1)
        var dbMask = MGF1.Generate(seed, k - hLen - 1);

        //6. To reverse step 6, recover the data block DB: DB = maskedDB XOR dbMask
        var db = XorByteArrays(maskedDB, dbMask);

        //7. to reverse step 3, split the data block into its parts: DB = lHash' || PS || 0x01 || M.
        // 1. Verify that
        //  - lHash' = lHash
        //  - PS only consists of bytes 0x00
        //  - PS and M are separated by the 0x01 yte and the first byte of EM is the byte 0x00.
        // 2. if any of these conditions arent met, then the padding is invalid.
        var (lHashPrime, ps, separator, m) = SplitDB(db, lhash.Length);
        return m;
    }

    public static (byte[], byte[], byte, byte[]) SplitDB(byte[] dataBlock, int lHashLength)
    {
        if (dataBlock == null || dataBlock.Length < lHashLength + 1)
        {
            throw new ArgumentException("Invalid data block length");
        }

        // Extract lHash'
        byte[] lHashPrime = new byte[lHashLength];
        Buffer.BlockCopy(dataBlock, 0, lHashPrime, 0, lHashLength);

        // Find the index of the first non-zero byte after lHash'
        int psIndex = Array.FindIndex(dataBlock, lHashLength, b => b != 0);

        // Extract PS
        byte[] ps = new byte[psIndex - lHashLength];
        Buffer.BlockCopy(dataBlock, lHashLength, ps, 0, ps.Length);

        // Extract 0x01
        byte separator = dataBlock[psIndex];

        // Extract M
        byte[] m = new byte[dataBlock.Length - psIndex - 1];
        Buffer.BlockCopy(dataBlock, psIndex + 1, m, 0, m.Length);

        return (lHashPrime, ps, separator, m);
    }

    private static (byte zero, byte[] maskedSeed, byte[] maskedDb) SplitEncodedMessage(byte[] encodedMessage, int hLen)
    {
        if (encodedMessage == null || encodedMessage.Length < 1 + hLen * 2)
        {
            throw new ArgumentException("Invalid encoded message length");
        }

        // Extract 0x00
        var firstByte = encodedMessage[0];

        // Extract maskedSeed
        var maskedSeed = new byte[hLen];
        Buffer.BlockCopy(encodedMessage, 1, maskedSeed, 0, hLen);

        // Extract maskedDB
        var maskedDB = new byte[encodedMessage.Length - 1 - hLen];
        Buffer.BlockCopy(encodedMessage, 1 + hLen, maskedDB, 0, maskedDB.Length);

        return (firstByte, maskedSeed, maskedDB);
    }

    public static byte[] Sha256(byte[] data)
    {
        using var sha256 = SHA256.Create();
        return sha256.ComputeHash(data);
    }

    public static byte[] Concat(params byte[][] arr)
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

    public static byte[] GenerateRandomBytes(int length)
    {
        var randomBytes = new byte[length];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return randomBytes;
    }

    public static byte[] XorByteArrays(byte[] array1, byte[] array2)
    {
        var length = Math.Min(array1.Length, array2.Length);
        var result = new byte[length];

        for (var i = 0; i < length; i++)
        {
            result[i] = (byte)(array1[i] ^ array2[i]);
        }

        return result;
    }

}