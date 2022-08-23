using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationAPI.Security
{
    public class AuthBaseDES
    {
        //--------------  DES Security -----------------
        private string DES_key = string.Empty; //必須8碼  
        private string DES_iv = string.Empty; //必須8碼

        public AuthBaseDES()
        {
            DES_key = "PNELSEMI";
            DES_iv = "pnelsemi";
        }

        public AuthBaseDES( string desKey, string desIV)
        {
            DES_key = desKey.Length == 8 ? desKey :"PNELSEMI";
            DES_iv = desIV.Length == 8 ? desIV : "pnelsemi";
        }

        public string EncryptDES(string body)
        {
            DESCryptoServiceProvider des = new DESCryptoServiceProvider();
            des.Key = Encoding.ASCII.GetBytes(DES_key);
            des.IV = Encoding.ASCII.GetBytes(DES_iv);
            byte[] s = Encoding.ASCII.GetBytes(body);
            ICryptoTransform desencrypt = des.CreateEncryptor();
            return (BitConverter.ToString(desencrypt.TransformFinalBlock(s, 0, s.Length)).Replace("-", string.Empty));
        }

        public string DecryptDES(string hexString)
        {
            try
            {
                DESCryptoServiceProvider des = new DESCryptoServiceProvider();
                des.Key = Encoding.ASCII.GetBytes(DES_key);
                des.IV = Encoding.ASCII.GetBytes(DES_iv);
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

    }
}
