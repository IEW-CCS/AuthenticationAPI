using AuthenticationAPI.Controllers;
using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AuthenticationAPI.Manager
{
    public class SecurityManager : ISecurityManager
    {
        private readonly ILogger<LoginController> _logger;
        private Thread _routineTask = null;
        private string _ManagerName = "SecurityManager";
        private ConcurrentDictionary<string, AuthSecurity> RSADict = null;

        public string ManageName
        {
            get
            {
                return this._ManagerName;
            }
        }

        public AuthSecurity GetRSASecurity(string Key, string Type)
        {
            string RSAKey = string.Concat(Key, "_", Type);
            return this.RSADict.GetOrAdd(RSAKey, new AuthSecurity()); 
        }

        public void SetRSASecurity(string Key, string Type, AuthSecurity Obj)
        {
            string RSAKey = string.Concat(Key, "_", Type);
            this.RSADict.AddOrUpdate(RSAKey, Obj, (key, oldvalue) => Obj);
        }


        public SecurityManager(ILogger<LoginController> logger)
        {
            _logger = logger;
            Init();
        }


        public void Init()
        {
           
            RSADict = new ConcurrentDictionary<string, AuthSecurity>();

            //-------- Restore in DB ------
            // default Assign one Sign in 簽章用RSA Module
            // 
            
        }


        public string EncryptByClientPublicKey(string Key, string Type, string Content, out string returnMsg)
        {
            string RSAKey = string.Concat(Key, "_", Type);
            AuthSecurity Auth =  this.RSADict.GetOrAdd(RSAKey, new AuthSecurity());
            returnMsg = string.Empty;


            if (Auth.EncryptByClientPublicKey(Content, out string encrypStr, out  returnMsg) == 0)
            {
                return encrypStr;
            }
            else
            {
                return null;
            }
        }

        public string DecryptByPrivateKey(string Key, string Type, string Content)
        {
            string RSAKey = string.Concat(Key, "_", Type);
            AuthSecurity Auth = this.RSADict.GetOrAdd(RSAKey, new AuthSecurity());

            if (Auth.DecryptByPrivateKey(Content, out string rawStr, out string returnMsg) == 0)
            {
                return rawStr;
            }
            else
            {
                return null;
            }
        }

        public string Encrypt_Sign(string Key, string Type, string Content, out string signString, out string returnMsg)
        {
            string RSAKey = string.Concat(Key, "_", Type);
            string rawStr = string.Empty;
            AuthSecurity Auth = this.RSADict.GetOrAdd(RSAKey, new AuthSecurity());

            if (Auth.Encrypt_Sign(Content, out rawStr,out signString, out returnMsg) == 0)
            {
                return rawStr;
            }
            else
            {
                return null;
            }
        }

        public string Decrypt_Check(string Key, string Type, string Content, string signString, out string returnMsg)
        {
            string RSAKey = string.Concat(Key, "_", Type);
            string rawStr = string.Empty;
            AuthSecurity Auth = this.RSADict.GetOrAdd(RSAKey, new AuthSecurity());

            if (Auth.Decrypt_Check(Content, signString, out rawStr, out returnMsg) == 0)
            {
                return rawStr;
            }
            else
            {
                return null;
            }
        }



    }
}
