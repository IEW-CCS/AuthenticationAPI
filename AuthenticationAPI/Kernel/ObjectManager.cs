using AuthenticationAPI.DBContext;
using AuthenticationAPI.DtoS;
using AuthenticationAPI.Structure;
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
        private ConcurrentDictionary<string, string> _CREDSIGN= null;

        //---- 暫時存放 ------
        private  ConcurrentDictionary<string, PassCode_Info> _passcode = null;
        private  ConcurrentDictionary<string, SerialNo_Info> _serialno = null;
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
            LoadCredentialSIGNFromDB();
        }

        public void init()
        {
            //---- Load from DB ----
            _CREDINFO = new ConcurrentDictionary<string, Credential_Info>();
            _CREDSIGN = new ConcurrentDictionary<string, string>();

            _registerStatus = new ConcurrentDictionary<string, string>();
            _hashPassword = new ConcurrentDictionary<string, string>();
            _verifyStatus = new ConcurrentDictionary<string, string>();
            _passcode = new ConcurrentDictionary<string, PassCode_Info>();
            _serialno = new ConcurrentDictionary<string, SerialNo_Info>();

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

        private void LoadCredentialSIGNFromDB()
        {
            using (var db = new DBContext.MetaDBContext(Provider, ConnectStr))
            {
                var userInfolist = db.auth_info.AsQueryable().ToList();
                foreach (var userInfo in userInfolist)
                {
                    this._CREDSIGN.AddOrUpdate(userInfo.username, userInfo.sign, (key, oldvalue) => userInfo.sign);
                }
            }
        }

        public Credential_Info GetCredInfo(string Key)
        {
            return this._CREDINFO.GetOrAdd(Key, new Credential_Info());
        }


        public void InitialCredInfo(string Key, Credential_Info Obj)
        {
            this._CREDINFO.AddOrUpdate(Key, Obj, (key, oldvalue) => Obj);
            try
            {
                using (var db = new DBContext.MetaDBContext(Provider, ConnectStr))
                {
                    var CredentialInfo = db.auth_cred.AsQueryable().Where(o => o.UserName == Key).FirstOrDefault();
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
                        CredentialInfo.CreateDateTime = Obj.CreateDateTime;
                        db.Attach(CredentialInfo).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
                    }
                    db.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Initial CredInfo Exception  Msg = " + ex.Message);
            }
        }


        public void SetCredInfo(string Key, Credential_Info Obj)
        {
            this._CREDINFO.AddOrUpdate(Key, Obj, (key, oldvalue) => Obj);
            try
            {
                using (var db = new DBContext.MetaDBContext(Provider, ConnectStr))
                {
                    var CredentialInfo = db.auth_cred.AsQueryable().Where(o => o.UserName == Key ).FirstOrDefault();
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
                        db.Attach(CredentialInfo).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
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

        public void SetCredSignDBTo(string username, string sign)
        {
            try
            {
                using (var db = new DBContext.MetaDBContext(Provider, ConnectStr))
                {
                    var UserInfo = db.auth_info.AsQueryable().Where(o => o.username == username).FirstOrDefault();
                    if (UserInfo != null)
                    {
                        UserInfo.sign = sign;
                        db.Attach(UserInfo).State = Microsoft.EntityFrameworkCore.EntityState.Modified;
                        db.SaveChanges();
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("SetDeviceMACInfo Exception  Msg = " + ex.Message);
            }
        }

        public  string GetCredentialSign(string Key)
        {
            if (this._CREDSIGN.TryGetValue(Key, out string credSign))
            {
                return credSign;
            }
            else
            {
                return null;
            }
        }
        public void SetCredentialSign(string Key, string credSign)
        {
            this._CREDSIGN.AddOrUpdate(Key, credSign, (key, oldvalue) => credSign);
            SetCredSignDBTo(Key, credSign);
        }

        public PassCode_Info GetPassCode(string Key)
        {
            PassCode_Info passcode = null;
            if (this._passcode.TryGetValue(Key, out passcode))
            {
                return passcode;
            }
            else
            {
                return null;
            }
        }
        public void SetPassCode(string Key, PassCode_Info passcode)
        {
            this._passcode.AddOrUpdate(Key, passcode, (key, oldvalue) => passcode);
        }

        public SerialNo_Info GetSerialNo(string Key)
        {
            SerialNo_Info serialNo = null;
            if (this._serialno.TryGetValue(Key, out serialNo))
            {
                return serialNo;
            }
            else
            {
                return null;
            }
        }
        public void SetSerialNo(string Key, SerialNo_Info serialNo)
        {
            this._serialno.AddOrUpdate(Key, serialNo, (key, oldvalue) => serialNo);
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
