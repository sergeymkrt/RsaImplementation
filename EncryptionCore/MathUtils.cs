using System.Numerics;
using System.Security.Cryptography;

namespace EncryptionCore;

public static class MathUtils
{
    public static bool IsProbablePrime(BigInteger n)
    {
        var rng = RandomNumberGenerator.Create();
        if (n == 2 || n == 3)
            return true;
        if (n < 2 || n % 2 == 0)
            return false;

        var d = n - 1;
        var s = 0;

        while (d % 2 == 0)
        {
            d /= 2;
            s += 1;
        }

        var bytes = new byte[n.ToByteArray().LongLength];
        rng.GetBytes(bytes);
        var a = new BigInteger(bytes);
        if (a < 2)
            a += 2;

        var x = BigInteger.ModPow(a, d, n);
        if (x == 1 || x == n - 1)
            return true;

        for (var r = 1; r < s; r++)
        {
            x = BigInteger.ModPow(x, 2, n);
            if (x == n - 1)
                return true;
        }

        return false;
    }

    public static BigInteger GenerateRandomPrime(int keySize)
    {
        var rng = RandomNumberGenerator.Create();
        while (true)
        {
            var bytes = new byte[keySize / 8];
            rng.GetBytes(bytes);
            var candidate = new BigInteger(bytes);
            candidate |= BigInteger.One; // Ensure odd number

            if (candidate.IsEven)
                candidate += BigInteger.One;

            if (IsProbablePrime(candidate))
                return candidate;
        }
    }


    public static void ExtendedEuclidean(BigInteger a, BigInteger b, out BigInteger gcd, out BigInteger x, out BigInteger y)
    {
        if (a == 0)
        {
            gcd = b;
            x = 0;
            y = 1;
        }
        else
        {
            ExtendedEuclidean(b % a, a, out gcd, out x, out y);
            var temp = x; // Store x in a temporary variable
            x = y - (b / a) * x;
            y = temp;
        }
    }

    public static bool IsLittleEndian()
    {
        return BitConverter.IsLittleEndian;
    }

}