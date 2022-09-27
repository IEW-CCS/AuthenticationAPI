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
    public class AAPSWREQService : IHttpTrxService
    {
        private string _SeviceName = TransService.AAPSWREQ.ToString();
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public AAPSWREQService(ILogger<ARREGCMPService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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
                string DecryptECS = string.Empty;
                string ReturnMsg = string.Empty;
                int ReturnCode = SecurityManager.GetRSASecurity(_userName, _deviceType).Decrypt_Check(Msg.ecs, Msg.ecssign, out DecryptECS, out ReturnMsg);
                if (ReturnCode != 0)
                {
                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, ReturnCode, ReturnMsg);
                    return HttpReply;
                }
                else
                {
                    ECS HESC = DeserializeObj._ECS(DecryptECS);
                    if (HESC == null)
                    {
                        int RTCode = (int)HttpAuthErrorCode.DecryptECSError;
                        HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                        return HttpReply;
                    }
                    else
                    {
                        string DecrypContent = this.DecryptDESData(HESC.Key, HESC.IV, Msg.datacontent);
                        if (DecrypContent == string.Empty)
                        {
                            int RTCode = (int)HttpAuthErrorCode.DecryptError;
                            HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                            return HttpReply;
                        }
                        else
                        {
                            AAPSWREQ aphpwreq = DeserializeObj._AHPWREQ(DecrypContent);
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
                    AuthDES DES = new AuthDES();
                    string DataContentDES = DES.EncryptDES(APHPWPLYJsonStr);

                    ECS HESC = new ECS();
                    HESC.Algo = "DES";
                    HESC.Key = DES.GetKey();
                    HESC.IV = DES.GetIV();


                    string ECSEncryptRetMsg = string.Empty;
                    string HESCJsonStr = JsonSerializer.Serialize(HESC);
                    string SignStr = string.Empty;
                    string ECSEncryptStr = SecurityManager.Encrypt_Sign(username, devicetype, HESCJsonStr, out SignStr, out ECSEncryptRetMsg);

                    if (ECSEncryptStr == string.Empty)
                    {
                        int RTCode = (int)HttpAuthErrorCode.ECSbyPublicKeyErrorRSA;
                        HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                        HttpReply.returnmsg += ", Error Msg = " + ECSEncryptRetMsg;
                        return HttpReply;
                    }
                    else
                    {
                        HttpReply = new HttpTrx();
                        HttpReply.username = username;
                        HttpReply.procstep = _replyProcessStep;
                        HttpReply.returncode = 0;
                        HttpReply.returnmsg = string.Empty;
                        HttpReply.datacontent = DataContentDES;
                        HttpReply.ecs = ECSEncryptStr;
                        HttpReply.ecssign = SignStr;

                    }
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
                // return string.Empty;
                 return "ABCD1234";
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
