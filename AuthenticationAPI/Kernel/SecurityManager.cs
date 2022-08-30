using AuthenticationAPI.Controllers;
using AuthenticationAPI.DBContext;
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
        private const string SIGNRSA = "signature";
        private string Provider = "MY_SQL";
        private string ConnectStr = "server= localhost;database=authapi;user=root;password=qQ123456";

        private readonly ILogger<LoginController> Logger; 
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

        public AuthSecurity SIGNRSASecurity()
        {
            AuthSecurity SignRSA = null;
            if (this.RSADict.TryGetValue(SIGNRSA,out SignRSA))
            {
                return SignRSA;
            }
            else
            {
                SignRSA = Reload_GenRSASign();
                return SignRSA;
            }   
        }


        public void SetRSASecurity(string Key, string Type, AuthSecurity Obj)
        {
            string RSAKey = string.Concat(Key, "_", Type);
          
        }


        public SecurityManager(ILogger<LoginController> _logger)
        {
            Logger = _logger;
            RSADict = new ConcurrentDictionary<string, AuthSecurity>();
         
        }

        public void InitFromDB(string _provider, string _connectionStr)
        {
            if(_provider != null)
            {
                Provider = _provider;
            }
            if(_connectionStr != null)
            {
                ConnectStr = _connectionStr;
            }
            LoadAuthConfFromDB();
            LoadAuthSecurityFromDB();
        }
   
        public void UpdateToDB( string username, string devicetype)
        {
            var AuthSecurityObject = GetRSASecurity(username, devicetype);
            using (var db = new DBContext.MetaDBContext(Provider, ConnectStr))
            {
                //----- 檢查DB是否存在簽章RSA資訊
                var authSecrity = db.auth_security.AsQueryable().Where(o => o.username == username && o.device_type == devicetype).FirstOrDefault();
                if (authSecrity == null)
                {
                    authSecrity = new AUTH_SECURITY();
                    authSecrity.username = username;
                    authSecrity.device_type = devicetype;
                    authSecrity.client_publickey = AuthSecurityObject.ClientPublicKey;
                    authSecrity.server_privatekey = AuthSecurityObject.PrivateKey;
                    authSecrity.server_publickey = AuthSecurityObject.PublicKey;
                    db.auth_security.Add(authSecrity);
                }
                else
                {
                    authSecrity.client_publickey = AuthSecurityObject.ClientPublicKey;
                    authSecrity.server_privatekey = AuthSecurityObject.PrivateKey;
                    authSecrity.server_publickey = AuthSecurityObject.PublicKey;
                }
                db.SaveChanges();
            }

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

        private void LoadAuthConfFromDB()
        {
            using (var db = new DBContext.MetaDBContext(Provider, ConnectStr))
            {
                //----- 檢查DB是否存在簽章RSA資訊
                var signRSA = db.auth_conf.AsQueryable().Where(o => o.function == SIGNRSA).FirstOrDefault();
                if (signRSA == null)
                {
                    AuthSecurity AuthSign = new AuthSecurity();
                    signRSA = new AUTH_CONF();
                    signRSA.function = SIGNRSA;
                    signRSA.item1 = AuthSign.PrivateKey;
                    signRSA.item2 = AuthSign.PublicKey;
                    db.auth_conf.Add(signRSA);
                    db.SaveChanges();
                }
                //------- Insert to Dict -----
                AuthSecurity AuthSecu = new AuthSecurity(signRSA.item1, signRSA.item2);
                this.RSADict.AddOrUpdate(SIGNRSA, AuthSecu, (key, oldvalue) => AuthSecu);
            }
        }

        private void LoadAuthSecurityFromDB()
        {
            using (var db = new DBContext.MetaDBContext(Provider, ConnectStr))
            {
                //----- 檢查DB是否存在使用者簽章RSA 
                var objSecuritys = db.auth_security.AsQueryable().ToList();
                foreach(AUTH_SECURITY obj in objSecuritys)
                {

                    AuthSecurity AuthObj = new AuthSecurity(obj.server_privatekey,obj.server_publickey);
                    AuthObj.ClientID = obj.username;
                    AuthObj.ClientPublicKey = obj.client_publickey;
                    string key = string.Concat(obj.username, "_", obj.device_type);
                    this.RSADict.AddOrUpdate(key, AuthObj, (key, oldvalue) => AuthObj);
                }
            }
        }

        private AuthSecurity Reload_GenRSASign()
        {
            AuthSecurity AuthSecu = null;
            using (var db = new DBContext.MetaDBContext(Provider, ConnectStr))
            {
                //----- 檢查DB是否存在 簽章RSA 資訊
                var signRSA = db.auth_conf.AsQueryable().Where(o => o.function == SIGNRSA).FirstOrDefault();
                if (signRSA == null)
                {
                    // 如果沒有就產生一組放置到DB中
                    AuthRSA RsaSign = new AuthRSA();
                    signRSA = new AUTH_CONF();
                    signRSA.function = SIGNRSA;
                    signRSA.item1 = RsaSign.privateKey;
                    signRSA.item2 = RsaSign.publicKey;
                    db.auth_conf.Add(signRSA);
                    db.SaveChanges();
                }
                //------- Insert to Dict -----
                AuthSecu = new AuthSecurity(signRSA.item1, signRSA.item2);
                this.RSADict.AddOrUpdate(SIGNRSA, AuthSecu, (key, oldvalue) => AuthSecu);
                return AuthSecu;
            }
        }
    }
}
