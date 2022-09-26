using AuthenticationAPI.DtoS;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthenticationAPI.Service
{
    public class AAUTHREQService : IHttpTrxService
    {
        private string _SeviceName = TransService.AAUTHREQ.ToString();
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public AAUTHREQService(ILogger<ARREGCMPService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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

            string _replyProcessStep = ProcessStep.AAUTHPLY.ToString();
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
                            AAUTHREQ apvryreq = DeserializeObj._APVRYREQ(DecrypContent);
                            if (apvryreq == null)
                            {
                                int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                                HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                                return HttpReply;
                            }
                            else
                            {
                                if (Handle_APVRYREQ(_userName, _deviceType, apvryreq) == false)
                                {
                                    int RTCode = (int)HttpAuthErrorCode.ServerProgressError;
                                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                                    return HttpReply;
                                }
                                else
                                {
                                    HttpReply = ReplyAPVRYPLY(_userName, _deviceType, apvryreq);
                                    return HttpReply;
                                }
                            }
                        }
                    }
                }
            }
        }

        private HttpTrx ReplyAPVRYPLY(string username, string devicetype, AAUTHREQ apvryreq)
        {
            HttpTrx HttpReply = null;
            AAUTHPLY Vryply = new AAUTHPLY();
            string _replyProcessStep = ProcessStep.AAUTHPLY.ToString();

            try
            {
                Vryply.SerialNo = GetSerialNo();
                string APVRYPLYJsonStr = System.Text.Json.JsonSerializer.Serialize(Vryply);
                AuthDES DES = new AuthDES();
                string DataContentDES = DES.EncryptDES(APVRYPLYJsonStr);

                ECS HESC = new ECS();
                HESC.Algo = "DES";
                HESC.Key = DES.GetKey();
                HESC.IV = DES.GetIV();

                string ECSEncryptRetMsg = string.Empty;
                string HESCJsonStr = JsonSerializer.Serialize(HESC);
                string ECSEncryptStr = SecurityManager.EncryptByClientPublicKey(username, devicetype, HESCJsonStr, out ECSEncryptRetMsg);

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

        private bool Handle_APVRYREQ(string username, string devicetype, AAUTHREQ apvryreq)
        {
            
            // --- Check PassWord and Pass Code ----

            return true;
        }

        private string GetSerialNo()
        {
            Random Rng = new Random((int)DateTime.Now.Millisecond);
            int R = Rng.Next(1, 255);
            return R.ToString();
        }



        private string GenerateHashPassWord(string username)
        {
            Random Rng = new Random((int)DateTime.Now.Millisecond);
            int R = Rng.Next(1, 255);
            Credential_Info cred = ObjectManagerInstance.GetCredInfo(username);
            cred.Nonce = R;
            string credJson = JsonSerializer.Serialize(cred);
            string SHAHW = Get_SHA1_Hash(credJson);
            return SHAHW.Substring(8);

        }


        private  string Get_SHA1_Hash(string value)
        {
            using var hash = SHA1.Create();
            var byteArray = hash.ComputeHash(Encoding.UTF8.GetBytes(value));
            return Convert.ToHexString(byteArray).ToLower();
        }


        private string GetHashPassWord(string username)
        {
            string hashPassword = GenerateHashPassWord(username);
            ObjectManagerInstance.SetHashPassword(username, hashPassword);
            return hashPassword;
        }
    }
}
