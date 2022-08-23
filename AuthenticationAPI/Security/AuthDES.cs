using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationAPI.Security
{
    public class AuthDES
    {
        private DESCryptoServiceProvider des = null;
        public AuthDES()
        {
            des = new DESCryptoServiceProvider();
            des.GenerateKey();
            des.GenerateIV();
        }

        public AuthDES( string key, string iv)
        {
            des = new DESCryptoServiceProvider();
            des.Key = StringToByteArray(key);
            des.IV = StringToByteArray(iv);
        }

        public string GetKey ()
        {
            return BitConverter.ToString(des.Key).Replace("-",""); 
        }

        public string  GetIV()
        {
            return BitConverter.ToString(des.IV).Replace("-", "");
        }

        public string EncryptDES(string body)
        {
            byte[] s = Encoding.ASCII.GetBytes(body);
            ICryptoTransform desencrypt = des.CreateEncryptor();
            return (BitConverter.ToString(desencrypt.TransformFinalBlock(s, 0, s.Length)).Replace("-", string.Empty));
        }

        public string DecryptDES(string hexString)
        {
            try
            {
                byte[] s = new byte[hexString.Length / 2];
                int j = 0;
                for (int i = 0; i < hexString.Length / 2; i++)
                {
                    s[i] = Byte.Parse(hexString[j].ToString() + hexString[j + 1].ToString(), System.Globalization.NumberStyles.HexNumber);
                    j += 2;
                }
                ICryptoTransform desencrypt = des.CreateDecryptor();
                return Encoding.ASCII.GetString(desencrypt.TransformFinalBlock(s, 0, s.Length));
            }
            catch
            {
                return hexString;
            }
        }

        private byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
