using System.Numerics;
using System.Text;

namespace RsaImplementation;

public static class CommonUtils
{
    public static void PrintToBase64(this byte[] bytes)
    {
        var base64 = Convert.ToBase64String(bytes);
        Console.WriteLine(base64);
    }
    
    public static void PrintToBase64(this BigInteger bigInteger)
    {
        var bytes = bigInteger.ToByteArray();
        bytes.PrintToBase64();
    }
    
    public static void PrintToUtf8(this byte[] bytes)
    {
        var utf8 = Encoding.UTF8.GetString(bytes);
        Console.WriteLine(utf8);
    }

    public static void PrintToUtf8(this BigInteger bigInteger)
    {
        var bytes = bigInteger.ToByteArray();
        var utf8 = Encoding.UTF8.GetString(bytes);
        Console.WriteLine(utf8);
    }
    
    public static byte[] ToByteArray(this string str)
    {
        return Encoding.UTF8.GetBytes(str);
    }
    
    public static string ToUtf8String(this byte[] bytes)
    {
        return Encoding.UTF8.GetString(bytes);
    }
    
    public static void SaveToFile(this byte[] bytes, string path)
    {
        File.WriteAllBytes(path, bytes);
    }
    
    public static void SaveToFile(this string str, string path)
    {
        File.WriteAllText(path, str);
    }
    
    public static string ReadFromFile(string path)
    {
        return File.ReadAllText(path);
    }
}