using Newtonsoft.Json;
using System;
using System.Security.Cryptography;
using System.Text;

namespace RSA_Sample
{
    internal class Program
    {
        /// <summary>
        /// 預先建立公私鑰,  公鑰給對方加密使用, 私鑰留給自己解密使用
        /// </summary>
        /// <param name="args"></param>
        private static void Main(string[] args)
        {
            // 建立RSA公私鑰
            var rsaEnc = new RSACryptoServiceProvider(2048);

            // 匯出公鑰(用於解密，檢驗簽章)，XML格式
            var pubKey = rsaEnc.ToXmlString(false);
            Console.WriteLine($"公鑰 {pubKey}");

            Console.WriteLine();
            Console.WriteLine("------------------------------------------------------");
            Console.WriteLine();

            // 匯出私鑰
            var rsaKeys = rsaEnc.ToXmlString(true);
            Console.WriteLine($"私鑰 {rsaKeys}");

            Console.WriteLine();
            Console.WriteLine("------------------------------------------------------");

            Console.WriteLine("加解密測試");

            Console.WriteLine();

            var param = new { A = "12345" };

            // 加密
            string encrypt = Encrypt(JsonConvert.SerializeObject(param), pubKey);
            Console.WriteLine($"以公鑰加密後 encrypt={encrypt}");

            Console.WriteLine();

            // 解密
            string result = Decrypt(encrypt, rsaKeys);
            Console.WriteLine($"以私鑰解密後 result={result}");

            Console.WriteLine();

            Console.WriteLine($"是否解密成功: {JsonConvert.SerializeObject(param).Equals(result)}");

            Console.ReadKey();
        }

        /// <summary>
        /// 加密後字串為 base64
        /// </summary>
        /// <param name="textToEncrypt">要加密的文字</param>
        /// <param name="publicKeyString">公鑰</param>
        /// <returns>密文</returns>
        public static string Encrypt(string textToEncrypt, string publicKeyString)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(textToEncrypt);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    rsa.FromXmlString(publicKeyString.ToString());
                    var encryptedData = rsa.Encrypt(bytesToEncrypt, RSAEncryptionPadding.Pkcs1);
                    var base64Encrypted = Convert.ToBase64String(encryptedData);
                    return base64Encrypted;
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="textToDecrypt">密文</param>
        /// <param name="privateKeyString">私鑰</param>
        /// <returns>解密後文字</returns>
        public static string Decrypt(string textToDecrypt, string privateKeyString)
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                try
                {
                    // server decrypting data with private key
                    rsa.FromXmlString(privateKeyString);

                    var resultBytes = Convert.FromBase64String(textToDecrypt);
                    var decryptedBytes = rsa.Decrypt(resultBytes, RSAEncryptionPadding.Pkcs1);
                    var decryptedData = Encoding.UTF8.GetString(decryptedBytes);
                    return decryptedData.ToString();
                }
                finally
                {
                    rsa.PersistKeyInCsp = false;
                }
            }
        }
    }
}