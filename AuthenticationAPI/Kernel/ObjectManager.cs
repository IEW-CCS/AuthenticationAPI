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
        private  ConcurrentDictionary<string, CREDINFO> _credInfo = null;
        private  ConcurrentDictionary<string, string> _deviceUUID = null;
        private  ConcurrentDictionary<string, string> _credential = null;
        private  ConcurrentDictionary<string, string> _registerStatus = null;

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
            _credInfo = new ConcurrentDictionary<string, CREDINFO>();
            _deviceUUID = new ConcurrentDictionary<string, string> ();
            _credential = new ConcurrentDictionary<string, string>();
            _registerStatus = new ConcurrentDictionary<string, string>();

        }

        public CREDINFO GetCredInfo(string Key)
        {
            return this._credInfo.GetOrAdd(Key, new CREDINFO());
        }
        public void SetCredInfo(string Key, CREDINFO Obj)
        {
            this._credInfo.AddOrUpdate(Key, Obj, (key, oldvalue) => Obj);
        }

        public string GetCredential(string Key)
        {
            return this._credential.GetOrAdd(Key, key =>
            {
                return string.Empty;
            });
        }
        public void SetCredential(string Key, string cred)
        {
            this._credential.AddOrUpdate(Key, cred, (key, oldvalue) => cred);
        }
        
       
        public void SetDeviceUUID(string Key, string uuid)
        {
            this._deviceUUID.AddOrUpdate(Key, uuid, (key, oldvalue) => uuid);
        }

        public string GetDeviceUUID(string Key)
        {
            return this._deviceUUID.GetOrAdd(Key, key =>
            {
                return string.Empty;
            });
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

    }
}
