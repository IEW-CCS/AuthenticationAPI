using AuthenticationAPI.DtoS;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;

namespace AuthenticationAPI.Service
{
    public class AAPSWREQServiceLite : IHttpTrxService
    {
        private string _SeviceName = TransServiceLite.AAPSWREQ_Lite.ToString();
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public AAPSWREQServiceLite(ILogger<ARREGCMPService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
        {
            Logger = logger;
            Configuration = configuration;
            SecurityManager = securitymanager;
            ObjectManagerInstance = (ObjectManager)objectmanager.GetInstance;
        }

        public string ServiceName
        {
            get
            {
                return this._SeviceName;
            }
        }

        public HttpTrx HandlepHttpTrx(HttpTrx Msg)
        {
            HttpTrx HttpReply = null;

            string _replyProcessStep = ProcessStep.AAPSWPLY.ToString();
            string _userName = Msg.username;
            string _deviceType = Msg.devicetype;

            if (_userName == string.Empty)
            {
                int RTCode = (int)HttpAuthErrorCode.UserNotExist;
                HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                return HttpReply;
            }
            else
            {
                AAPSWREQ aphpwreq = DeserializeObj._AHPWREQ(Msg.datacontent);
                if (aphpwreq == null)
                {
                    int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                    return HttpReply;
                }
                else
                {
                    if (Handle_APHPWREQ(_userName, _deviceType, aphpwreq) == false)
                    {
                        int RTCode = (int)HttpAuthErrorCode.ServerProgressError;
                        HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                        return HttpReply;
                    }
                    else
                    {
                        HttpReply = this.ReplyAPHPWPLY(_userName, _deviceType, aphpwreq);
                        return HttpReply;
                    }
                }


            }
        }


        //---- Re modify 
        private HttpTrx ReplyAPHPWPLY(string username, string devicetype, AAPSWREQ aphpwreq)
        {
            HttpTrx HttpReply = null;
            string _replyProcessStep = ProcessStep.AAPSWPLY.ToString();

            try
            {
                string hashPassword = GenerateHashPassWord(username);
                if (hashPassword == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.HashPasswordCreateError;
                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                    return HttpReply;
                }
                else
                {
                    AAPSWPLY aphpwply = new AAPSWPLY();
                    aphpwply.PassWordData = hashPassword;
                    string APHPWPLYJsonStr = System.Text.Json.JsonSerializer.Serialize(aphpwply);

                    HttpReply = new HttpTrx();
                    HttpReply.username = username;
                    HttpReply.procstep = _replyProcessStep;
                    HttpReply.returncode = 0;
                    HttpReply.returnmsg = string.Empty;
                    HttpReply.datacontent = APHPWPLYJsonStr;
                    HttpReply.ecs = string.Empty;
                    HttpReply.ecssign = string.Empty;
                }
            }
            catch (Exception ex)
            {
                HttpReply = HttpReplyNG.Trx(_replyProcessStep, ex);
            }
            return HttpReply;
        }

        private string DecryptDESData(string key, string iv, string DataContent)
        {
            AuthDES objDes = new AuthDES(key, iv);
            string DES_DecryptStr = string.Empty;
            try
            {
                DES_DecryptStr = objDes.DecryptDES(DataContent);
            }
            catch
            {
                DES_DecryptStr = string.Empty;
            }
            return DES_DecryptStr;
        }

        private bool Handle_APHPWREQ(string username, string devicetype, AAPSWREQ aphpwreq)
        {
            //---暫時 Always Return True 以後有想到邏輯再補上
  
            return true;
        }

        private string GenerateHashPassWord(string username)
        {
            try
            {
                Random Rng = new Random((int)DateTime.Now.Millisecond);
                int R = Rng.Next(1, 255);
                Credential_Info cred = ObjectManagerInstance.GetCredInfo(username);
                cred.Nonce = R;
                //string credJson = JsonSerializer.Serialize(cred);
                string SHAHW = Get_SHA1_Hash(cred);
                return SHAHW;
            }
            catch
            {
                return string.Empty;
            }
        }


        private string Get_SHA1_Hash(string value)
        {
            using var hash = SHA1.Create();
            var byteArray = hash.ComputeHash(Encoding.UTF8.GetBytes(value));
            return Convert.ToHexString(byteArray).ToLower();
        }

        private string Get_SHA1_Hash(object value)
        {
            using var hash = SHA1.Create();
            var byteArray = hash.ComputeHash(ObjectToByteArray(value));
            return Convert.ToHexString(byteArray).ToLower();
        }

        private string GetHashPassWord(string username)
        {
            string hashPassword = GenerateHashPassWord(username);
            if (hashPassword != string.Empty)
            {
                ObjectManagerInstance.SetHashPassword(username, hashPassword);
            }
            return hashPassword;
        }


        private byte[] ObjectToByteArray(object obj)
        {
            if (obj == null)
                return null;
            BinaryFormatter bf = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, obj);
                return ms.ToArray();
            }
        }
    }
}
