using AuthenticationAPI.DBContext;
using AuthenticationAPI.DtoS;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.Kernel
{
    public class ObjectManager : IObjectManager
    {
        private string Provider = "MY_SQL";
        private string ConnectStr = "server= localhost;database=authapi;user=root;password=qQ123456";

        //---- 長期存放資料需要存放進DB ------
        private  ConcurrentDictionary<string, Credential_Info> _CREDINFO= null;

        //---- 暫時存放 ------
        private  ConcurrentDictionary<string, Credential> _credential = null;
        private  ConcurrentDictionary<string, string> _registerStatus = null;
        private  ConcurrentDictionary<string, string> _verifyStatus = null;
        private  ConcurrentDictionary<string, string> _hashPassword = null;

        public ObjectManager()
        {
            init();
        }

        public object GetInstance
        {
            get
            {
                return this;
            }

        }

        public void InitFromDB(string _provider, string _connectionStr)
        {
            //-------------------------------------
            if (_provider != null)
            {
                Provider = _provider;
            }
            //-------------------------------------
            if (_connectionStr != null)
            {
                ConnectStr = _connectionStr;
            }
          
            LoadCredentialInfoFromDB();
        }

        public void init()
        {
            //---- Load from DB ----
            _CREDINFO = new ConcurrentDictionary<string, Credential_Info>();

            _credential = new ConcurrentDictionary<string, Credential>();
            _registerStatus = new ConcurrentDictionary<string, string>();
            _hashPassword = new ConcurrentDictionary<string, string>();
            _verifyStatus = new ConcurrentDictionary<string, string>();

        }

        private void LoadCredentialInfoFromDB()
        {
            using (var db = new DBContext.MetaDBContext(Provider, ConnectStr))
            {
                var CredentialInfoList = db.auth_cred.AsQueryable().ToList();
                foreach ( var cred in CredentialInfoList)
                {
                    Credential_Info tmpCredInfo = new Credential_Info();
                    tmpCredInfo.UserName = cred.UserName;
                    tmpCredInfo.APPGuid = cred.APPGuid;
                    tmpCredInfo.APPVersion = cred.APPVersion;
                    tmpCredInfo.DeviceUUID = cred.DeviceUUID;
                    tmpCredInfo.Nonce = cred.Nonce;
                    tmpCredInfo.CreateDateTime = cred.CreateDateTime;
                    this._CREDINFO.AddOrUpdate(cred.UserName, tmpCredInfo, (key, oldvalue) => tmpCredInfo);
                }
            }
        }

        public Credential_Info GetCredInfo(string Key)
        {
            return this._CREDINFO.GetOrAdd(Key, new Credential_Info());
        }
        public void SetCredInfo(string Key, Credential_Info Obj)
        {
            this._CREDINFO.AddOrUpdate(Key, Obj, (key, oldvalue) => Obj);
            try
            {
                using (var db = new DBContext.MetaDBContext(Provider, ConnectStr))
                {
                    var CredentialInfo = db.auth_cred.AsQueryable().Where(o => o.UserName == Key && DateTime.Equals(o.CreateDateTime, Obj.CreateDateTime)).FirstOrDefault();
                    if (CredentialInfo == null)
                    {
                        CredentialInfo = new AUTH_CRED();
                        CredentialInfo.UserName = Obj.UserName;
                        CredentialInfo.APPGuid = Obj.APPGuid;
                        CredentialInfo.APPVersion = Obj.APPVersion;
                        CredentialInfo.DeviceUUID = Obj.DeviceUUID;
                        CredentialInfo.Nonce = Obj.Nonce;
                        CredentialInfo.CreateDateTime = Obj.CreateDateTime;
                        db.auth_cred.Add(CredentialInfo);
                    }
                    else
                    {
                        CredentialInfo.UserName = Obj.UserName;
                        CredentialInfo.APPGuid = Obj.APPGuid;
                        CredentialInfo.APPVersion = Obj.APPVersion;
                        CredentialInfo.DeviceUUID = Obj.DeviceUUID;
                        CredentialInfo.Nonce = Obj.Nonce;
                    }
                    db.SaveChanges();
                }
            }
            catch(Exception ex)
            {
                throw new Exception ( "SetCredInfo Exception  Msg = " + ex.Message);
            }
        }

        public void SetDeviceMACInfo(string deviceMacAddress)
        {
            try
            {
                using (var db = new DBContext.MetaDBContext(Provider, ConnectStr))
                {
                    var DeviceInfo = db.auth_device.AsQueryable().Where(o => o.device == deviceMacAddress).FirstOrDefault();
                    if (DeviceInfo == null)
                    {
                        DeviceInfo = new AUTH_DEVICE();
                        DeviceInfo.device = deviceMacAddress;
                        db.auth_device.Add(DeviceInfo);
                        db.SaveChanges();
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("SetDeviceMACInfo Exception  Msg = " + ex.Message);
            }
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
