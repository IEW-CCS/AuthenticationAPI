using AuthenticationAPI.DtoS;
using AuthenticationAPI.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI
{

    public interface IService
    {
        string ServiceName
        {
            get;
        }
    }
    interface IManagement
    {
        string ManageName
        {
            get;
        }

    
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

        public CREDINFO GetCredInfo(string Key);
        public void SetCredInfo(string Key, CREDINFO Obj);

        public string GetDeviceUUID(string Key);
        public void SetDeviceUUID(string Key, string uuid);
       
    }


    public interface ISecurityManager
    {
        string ManageName
        {
            get;
        }

        public void InitFromDB(string Type, string ConnectionStr);
        public void UpdateToDB(string username, string devicetype);
        public AuthSecurity GetRSASecurity(string Key, string Type);
        public void SetRSASecurity(string Key, string Type, AuthSecurity Obj);
        public string EncryptByClientPublicKey(string Key, string Type,string Content, out string returnMsg);
        public string DecryptByPrivateKey(string Key, string Type, string Content);
        public string Encrypt_Sign(string Key, string Type, string Content, out string signString, out string returnMsg);
        public string Decrypt_Check(string Key, string Type, string Content, string signString, out string returnMsg);


    }

}
