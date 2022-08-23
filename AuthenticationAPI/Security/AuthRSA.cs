using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace AuthenticationAPI.Security
{
    public class AuthRSA
    {
        public string publicKey { get; } = string.Empty;
        public string privateKey { get; } = string.Empty;
        public AuthRSA()
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            this.publicKey = rsa.ToXmlString(false);
            this.privateKey = rsa.ToXmlString(true);
        }

        public AuthRSA(string _privateKey)
        {
            this.publicKey = string.Empty;
            this.privateKey = _privateKey;
        }

        public AuthRSA(string _privateKey, string _publicKey)
        {
            this.publicKey = _publicKey;
            this.privateKey = _privateKey;
        }
    }
}
