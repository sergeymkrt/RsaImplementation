using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionCore;

public class Rsa
{
    private readonly BigInteger _p;
    private readonly BigInteger _q;
    private readonly BigInteger _n;
    private BigInteger Phi => (_p - 1) * (_q - 1);
    private readonly BigInteger _e;
    private readonly BigInteger _d;
    private bool _isImported;
    public int KeySize { get; set; }

    protected Rsa()
    {
    }

    public Rsa(int keysize)
    {
        _p = MathUtils.GenerateRandomPrime(keysize / 2);
        _q = MathUtils.GenerateRandomPrime(keysize / 2);
        _n = _p * _q;
        _e = CalculateE(Phi);
        _d = CalculateD(_e, Phi);
        _isImported = false;
        KeySize = keysize;
    }

    public Rsa(string publicKey, string privateKey)
    {
        var publicKeyLines = publicKey.Split("\r\n");
        var privateKeyLines = privateKey.Split("\r\n");
        var nBytes = Convert.FromBase64String(publicKeyLines[1]);
        var eBytes = Convert.FromBase64String(publicKeyLines[2]);
        var dBytes = Convert.FromBase64String(privateKeyLines[2]);
        _n = new BigInteger(nBytes);
        _e = new BigInteger(eBytes);
        _d = new BigInteger(dBytes);
        _isImported = true;
        KeySize = _n.ToByteArray().Length * 8;
    }

    public static Rsa ImportFromPath(string publicKeyPath, string privateKeyPath)
    {
        var publicKey = CommonUtils.ReadFromFile(publicKeyPath);
        var privateKey = CommonUtils.ReadFromFile(privateKeyPath);
        return new Rsa(publicKey, privateKey);
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
        var nBytes = _n.ToByteArray();
        var eBytes = _e.ToByteArray();
        sb.AppendLine(Convert.ToBase64String(nBytes));
        sb.AppendLine(Convert.ToBase64String(eBytes));
        sb.AppendLine("-----END RSA PUBLIC KEY-----");
        return sb.ToString();
    }

    public string PrintPrivateKey()
    {
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
        var nBytes = _n.ToByteArray();
        var dBytes = _d.ToByteArray();
        sb.AppendLine(Convert.ToBase64String(nBytes));
        sb.AppendLine(Convert.ToBase64String(dBytes));
        sb.AppendLine("-----END RSA PRIVATE KEY-----");
        return sb.ToString();
    }

    public BigInteger Encrypt(BigInteger message)
    {
        if (message.ToByteArray() == Array.Empty<byte>())
        {
            return message;
        }

        //check if message bitsize is smaller than n
        if (message.ToByteArray().Length > KeySize / 8)
        {
            throw new ArgumentException("Message is too large to be encrypted with the given public key.");
        }

        return BigInteger.ModPow(message, _e, _n);
    }

    public BigInteger EncryptWithOAEP(BigInteger message)
    {
        //check if message bitsize is smaller than n
        if (message.ToByteArray().Length > KeySize / 8)
        {
            throw new ArgumentException("Message is too large to be encrypted with the given public key.");
        }

        var paddedMessage = OAEP.Encode(message.ToByteArray(), KeySize);

        // Reversing the message to avoid negative numbers
        var reversedMessage = paddedMessage.Reverse().ToArray();
        return BigInteger.ModPow(new BigInteger(reversedMessage), _e, _n);
    }

    public BigInteger Decrypt(BigInteger encryptedMessage)
    {
        if (encryptedMessage.ToByteArray() == Array.Empty<byte>())
        {
            return encryptedMessage;
        }

        if (encryptedMessage.ToByteArray().Length > KeySize / 8)
        {
            throw new ArgumentException("Message is too large to be encrypted with the given public key.");
        }

        return BigInteger.ModPow(encryptedMessage, _d, _n);
    }

    public byte[] DecryptWithOAEP(BigInteger encryptedMessage)
    {
        if (encryptedMessage.ToByteArray().Length > KeySize / 8)
        {
            throw new ArgumentException("Message is too large to be encrypted with the given public key.");
        }
        var decrypted = BigInteger.ModPow(encryptedMessage, _d, _n).ToByteArray();

        //Reversing back to original order

        var decryptedReversed = decrypted.Reverse().ToArray();
        var decryptedMessage = OAEP.Decode(decryptedReversed, KeySize);

        return decryptedMessage;
    }

}