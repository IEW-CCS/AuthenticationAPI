using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AuthenticationAPI.Security
{
    public class AuthSecurity
    {
        private string ClientID = string.Empty;
        private string ClientPublicKey = string.Empty;
      
        //-----------------------------------------------
        private AuthRSA objAuthRSA = null;
        private AuthBaseDES objAuthBaseDES = null;

        public AuthSecurity()
        {
            objAuthRSA = new AuthRSA();
            objAuthBaseDES = new AuthBaseDES();
            ClientID = string.Empty;
            ClientPublicKey = objAuthRSA.publicKey;
           // ClientPublicKey = string.Empty;

        }

        public AuthSecurity(string _privateKey)
        {
            objAuthBaseDES = new AuthBaseDES();
            string PrivateKey = objAuthBaseDES.DecryptDES(_privateKey);
            objAuthRSA = new AuthRSA(PrivateKey);
            ClientID = string.Empty;
            ClientPublicKey = string.Empty; 
        }

        public AuthSecurity(string _privateKey, string _publicKey)
        {
            objAuthBaseDES = new AuthBaseDES();
            string PrivateKey = objAuthBaseDES.DecryptDES(_privateKey);
            string PublicKey = _publicKey;
            objAuthRSA = new AuthRSA(PrivateKey, PublicKey);
            ClientID = string.Empty;
            ClientPublicKey = string.Empty;
          
        }
        //-----------------------------------------------
        public string PrivateKey
        {
            get { return objAuthBaseDES.EncryptDES(objAuthRSA.privateKey); }
        }

        public string PublicKey
        {
            get { return objAuthRSA.publicKey; }
        }

        public string setClientID
        {
            get { return ClientID; }
            set { ClientID = value; }
        }

        public string setClientPublicKey
        {
            get { return ClientPublicKey; }
            set { ClientPublicKey = value; }
        }

    
        public int EncryptByClientPublicKey(string rawContent, out string encryptString, out string returnMsg)
        {
            returnMsg = string.Empty;
            encryptString = string.Empty;
            int returnCode = 0;

            if (ClientPublicKey == string.Empty)
            {
                returnMsg = "Client Public Key Not Exit";
                encryptString = string.Empty;
                returnCode = 1;
            }
            else
            {
                try
                {
                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    byte[] terst = Encoding.UTF8.GetBytes(rawContent);
                    rsa.FromXmlString(ClientPublicKey);
                    encryptString = Convert.ToBase64String(rsa.Encrypt(Encoding.UTF8.GetBytes(rawContent), false));
                    returnMsg = string.Empty;
                    returnCode = 0;
                }
                catch (Exception ex)
                {
                    returnMsg = "Exception, Msg = " + ex.Message.ToString();
                    encryptString = string.Empty;
                    returnCode = 2;
                }
            }
            return returnCode;
        }

        public int DecryptByPrivateKey(string encryptedContent, out string rawContent, out string returnMsg)
        {
            returnMsg = string.Empty;
            rawContent = string.Empty;
            int returnCode = 0;

            if (objAuthRSA.privateKey == string.Empty)
            {
                returnMsg = "Private Key Not Exit";
                rawContent = string.Empty;
                returnCode = 1;
            }
            else
            {
                try
                {
                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    rsa.FromXmlString(objAuthRSA.privateKey);
                    rawContent = Encoding.UTF8.GetString(rsa.Decrypt(Convert.FromBase64String(encryptedContent), false));
                    returnMsg = string.Empty;
                    returnCode = 0;
                }
                catch (Exception ex)
                {
                    returnMsg = "Exception, Msg = " + ex.Message.ToString();
                    rawContent = string.Empty;
                    returnCode = 2;
                }
            }
            return returnCode;
        }


        public int SignString(string rawContent, out string signString, out string returnMsg)
        {
            signString = string.Empty;
            returnMsg = string.Empty;
            int returnCode = 0;

            if (objAuthRSA.privateKey == string.Empty)
            {
                returnMsg = "Private Key Not Exit";
                rawContent = string.Empty;
                returnCode = 1;
            }
            else
            {
                try
                {
                    //進行簽章(假設我們使用SHA256)
                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    byte[] plainText = Encoding.Unicode.GetBytes(rawContent);
                    byte[] signText = rsa.SignData(plainText, new SHA256CryptoServiceProvider());
                    signString = Convert.ToBase64String(signText);
                    returnMsg = string.Empty;
                    returnCode = 0;
                }
                catch (Exception ex)
                {
                    returnMsg = "Exception, Msg = " + ex.Message.ToString();
                    rawContent = string.Empty;
                    returnCode = 2;
                }
            }
            return returnCode;
        }

        public int CheckSignString(string DataString, string signString, out string returnMsg)
        {
            byte[] DataText = Encoding.Unicode.GetBytes(DataString);
            byte[] signText = Encoding.Unicode.GetBytes(signString);
            returnMsg = string.Empty;
            int returnCode = 0;
            if (ClientPublicKey == string.Empty)
            {
                returnMsg = "Private Key Not Exit";
                returnCode = 2;
            }
            else
            {
                try
                {
                    RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                    rsa.FromXmlString(ClientPublicKey);
                    if (rsa.VerifyData(DataText, new SHA256CryptoServiceProvider(), signText))
                    {
                        returnMsg = String.Empty;
                        returnCode = 0;
                    }
                    else
                    {
                        returnMsg = "VerifyData Not Match";
                        returnCode = 1;
                    }
                }
                catch (Exception ex)
                {
                    returnMsg = "Exception, Msg = " + ex.Message.ToString();
                    returnCode = 3;
                }
            }
            return returnCode;
        }

        public int Encrypt_Sign(string rawContent, out string encryptString, out string signString, out string returnMsg)
        {
            encryptString = string.Empty;
            signString = string.Empty;
            returnMsg = string.Empty;
            int returnCode = 0;

            if (ClientPublicKey == string.Empty)
            {
                returnMsg = "Client Public Key Not Exit";
                encryptString = string.Empty;
                returnCode = 1;
            }
            else if (objAuthRSA.privateKey == string.Empty)
            {
                returnMsg = "Private Key Not Exit";
                rawContent = string.Empty;
                returnCode = 1;
            }
            else
            {
                try
                {
                    if (EncryptByClientPublicKey(rawContent, out encryptString, out returnMsg) == 0)
                    {
                        returnCode = 0;
                        returnMsg = string.Empty;
                        if (SignString(encryptString, out signString, out returnMsg) == 0)
                        {
                            returnCode = 0;
                            returnMsg = string.Empty;
                        }
                        else
                        {
                            returnMsg = "Sign by Private Key Error, Msg = " + returnMsg;
                            encryptString = string.Empty;
                            returnCode = 4;
                        }
                    }
                    else
                    {
                        returnMsg = "Encrypt By Client Public Key Error, Msg = " + returnMsg;
                        encryptString = string.Empty;
                        returnCode = 3;
                    }
                }
                catch (Exception ex)
                {
                    returnMsg = "Exception, Msg = " + ex.Message.ToString();
                    encryptString = string.Empty;
                    returnCode = 2;
                }
            }
            return returnCode;
        }

        public int Decrypt_Check(string encryptedContent, string signString, out string rawContent, out string returnMsg)
        {
            returnMsg = string.Empty;
            rawContent = string.Empty;
            int returnCode = 0;

            if (ClientPublicKey == string.Empty)
            {
                returnMsg = "Client Public Key Not Exit";
                rawContent = string.Empty;
                returnCode = 1;
            }
            else if (objAuthRSA.privateKey == string.Empty)
            {
                returnMsg = "Private Key Not Exit";
                rawContent = string.Empty;
                returnCode = 1;
            }
            else
            {
                try
                {
                    if (CheckSignString(encryptedContent, signString, out returnMsg) == 0)
                    {
                        returnCode = 0;
                        returnMsg = string.Empty;
                        if (DecryptByPrivateKey(encryptedContent, out rawContent, out returnMsg) == 0)
                        {
                            returnCode = 0;
                            returnMsg = string.Empty;
                        }
                        else
                        {
                            returnMsg = "Decrypt By PrivateKey Error, Msg = " + returnMsg;
                            returnCode = 4;
                        }
                    }
                    else
                    {
                        returnMsg = "Sign Check Mismatch, Msg = " + returnMsg;
                        returnCode = 3;
                    }
                }
                catch (Exception ex)
                {
                    returnMsg = "Exception, Msg = " + ex.Message.ToString();
                    returnCode = 2;
                }
            }
            return returnCode;
        }
    }
}
