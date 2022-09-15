﻿using AuthenticationAPI.DtoS;
using AuthenticationAPI.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI
{

    public interface IHttpTrxService
    {
        string ServiceName
        {
            get;
        }

        public HttpTrx HandlepHttpTrx(HttpTrx Msg);
    }

    interface IManagement
    {
        string ManageName
        {
            get;
        }

    
    }


    interface IAuthenticate
    {
        string AuthenticateName
        {
            get;
        }
        bool CheckAuth(object Obj, out string RetMsg);
    }


    interface ILDAPManagement
    {
        string ManageName
        {
            get;
        }

        public void Init();
        public bool ModifyUserPassword(string username, string password);

    }

    public interface IQueueManager
    {

        void PutMessage(Kernel.MessageTrx msg);

        Kernel.MessageTrx GetMessage();

        int GetCount();

        void ClearQueue();
    }

    public interface IMessageManager
    {
        void MessageDispatch(string name, object[] parameters);
    }


    public interface IObjectManager
    {
        object GetInstance
        {
            get;
        }
    }


    public interface ISecurityManager
    {
        string ManageName
        {
            get;
        }

        public void InitFromDB(string Type, string ConnectionStr);
        public void UpdateAuthSecurityToDB(string username, string devicetype);
        public AuthSecurity GetRSASecurity(string Key, string Type);
        public AuthSecurity SIGNRSASecurity();
        public void SetRSASecurity(string Key, string Type, AuthSecurity Obj);
        public string EncryptByClientPublicKey(string Key, string Type,string Content, out string returnMsg);
        public string DecryptByPrivateKey(string Key, string Type, string Content);
        public string Encrypt_Sign(string Key, string Type, string Content, out string signString, out string returnMsg);
        public string Decrypt_Check(string Key, string Type, string Content, string signString, out string returnMsg);

    }

}
