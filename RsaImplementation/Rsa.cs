using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RsaImplementation;

public class Rsa : IEncryption
{
    public readonly BigInteger p;
    public readonly BigInteger q;
    public BigInteger n => p * q;
    public BigInteger phi => (p - 1) * (q - 1);
    public readonly BigInteger e;
    public readonly BigInteger d;
    
    public Rsa(int keysize)
    {
        p = MathUtils.GenerateRandomPrime(keysize/2);
        q = MathUtils.GenerateRandomPrime(keysize/2);
        e = CalculateE(phi);
        d = CalculateD(e, phi);
    }
    
    private BigInteger CalculateE(BigInteger phiN)
    {
        var rng = RandomNumberGenerator.Create();
        
        var bitLength = 17; // Fixed bit length for e
        var byteLength = (int)Math.Ceiling(bitLength / 8.0);

        while (true)
        {
            var bytes = new byte[byteLength];
            rng.GetBytes(bytes);
            var candidate = new BigInteger(bytes);
            candidate |= BigInteger.One; // Ensure odd number

            if (candidate < phiN && candidate > 0 && BigInteger.GreatestCommonDivisor(candidate, phiN) == 1)
                return candidate;
        }
    }
    
    
    private BigInteger CalculateD(BigInteger e, BigInteger phiN)
    {
        BigInteger gcd, x, y;
        MathUtils.ExtendedEuclidean(e, phiN, out gcd, out x, out y);

        // Ensure d is positive
        if (x < 0)
            x += phiN;

        return x;
    }

    public string PrintPublicKey()
    {
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN RSA PUBLIC KEY-----");
        var nBytes = n.ToByteArray();
        var eBytes = e.ToByteArray();
        sb.AppendLine(Convert.ToBase64String(nBytes));
        sb.AppendLine(Convert.ToBase64String(eBytes));
        sb.AppendLine("-----END RSA PUBLIC KEY-----");
        return sb.ToString();
    }
    
    public string PrintPrivateKey()
    {
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
        var nBytes = n.ToByteArray();
        var dBytes = d.ToByteArray();
        sb.AppendLine(Convert.ToBase64String(nBytes));
        sb.AppendLine(Convert.ToBase64String(dBytes));
        sb.AppendLine("-----END RSA PRIVATE KEY-----");
        return sb.ToString();
    }

    public BigInteger Encrypt(BigInteger message)
    {
        if (message >= n)
        {
            throw new ArgumentException("Message is too large to be encrypted with the given public key.");
        }
        return BigInteger.ModPow(message, e, n);
    }

    public BigInteger Decrypt(BigInteger encryptedMessage)
    {
        if (encryptedMessage >= n)
        {
            throw new ArgumentException("Encrypted message is too large to be decrypted with the given private key.");
        }
        return BigInteger.ModPow(encryptedMessage, d, n);
    }
    
}