using AuthenticationAPI.DtoS;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.Kernel
{
    public class ObjectManager : IObjectManager
    {
        private  ConcurrentDictionary<string, CRED_INFO> _credInfo = null;
        private  ConcurrentDictionary<string, Credential> _credential = null;
        private  ConcurrentDictionary<string, string> _registerStatus = null;
        private  ConcurrentDictionary<string, string> _verifyStatus = null;
        private  ConcurrentDictionary<string, string> _hashPassword = null;


        public ObjectManager()
        {
            Init();
        }

        public object GetInstance
        {
            get
            {
                return this;
            }

        }

        private void Init()
        {
            _credInfo = new ConcurrentDictionary<string, CRED_INFO>();
            _credential = new ConcurrentDictionary<string, Credential>();
            _registerStatus = new ConcurrentDictionary<string, string>();
            _hashPassword = new ConcurrentDictionary<string, string>();
        }

        public CRED_INFO GetCredInfo(string Key)
        {
            return this._credInfo.GetOrAdd(Key, new CRED_INFO());
        }
        public void SetCredInfo(string Key, CRED_INFO Obj)
        {
            this._credInfo.AddOrUpdate(Key, Obj, (key, oldvalue) => Obj);
        }

        public Credential GetCredential(string Key)
        {
            Credential Cred = null;
            if (this._credential.TryGetValue(Key, out Cred))
            {
                return Cred;
            }
            else
            {
                return null;
            }
        }
        public void SetCredential(string Key, Credential cred)
        {
            this._credential.AddOrUpdate(Key, cred, (key, oldvalue) => cred);
        }
        
       
        public string GetVerifyStatus(string Key)
        {
            return this._verifyStatus.GetOrAdd(Key, key =>
            {
                return string.Empty; 
            });
        }
        public void SetVerifyStatus(string Key, string status)
        {
            this._verifyStatus.AddOrUpdate(Key, status, (key, oldvalue) => status);
        }



        public string GetRegisterStatus(string Key)
        {
            return this._registerStatus.GetOrAdd(Key, key =>
            {
                return string.Empty;
            });
        }
        public void SetRegisterStatus(string Key, string status)
        {
            this._registerStatus.AddOrUpdate(Key, status, (key, oldvalue) => status);
        }

        public string GetHashPassword(string Key)
        {
            return this._hashPassword.GetOrAdd(Key, key =>
            {
                return string.Empty;
            });
        }

        public void SetHashPassword(string Key, string HashPassword)
        {
            this._hashPassword.AddOrUpdate(Key, HashPassword, (key, oldvalue) => HashPassword);
        }



    }
}
