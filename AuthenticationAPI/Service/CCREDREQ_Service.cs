using AuthenticationAPI.DtoS;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthenticationAPI.Service
{
    public class CCREDREQ_Service : IHttpTrxService
    {
        private string _SeviceName = "CCREDREQ";
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public CCREDREQ_Service(ILogger<CCREDREQ_Service> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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

            string _replyProcessStep = ProcessStep.CRED_PLY.ToString();
            string _userName = Msg.UserName;
            string _deviceType = Msg.DeviceType;

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
                int ReturnCode = SecurityManager.GetRSASecurity(_userName, _deviceType).Decrypt_Check(Msg.ECS, Msg.ECSSign, out DecryptECS, out ReturnMsg);
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
                        string DecrypContent = this.DecryptDESData(HESC.Key, HESC.IV, Msg.DataContent);
                        if (DecrypContent == string.Empty)
                        {
                            int RTCode = (int)HttpAuthErrorCode.DecryptError;
                            HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                            return HttpReply;
                        }
                        else
                        {
                            CCREDREQ ccredreq = DeserializeObj._CCREDREQ(DecrypContent);
                            if (ccredreq == null)
                            {
                                int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                                HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                                return HttpReply;
                            }
                            else
                            {
                                if (Handle_CCREDREQ(_userName, _deviceType, ccredreq) == false)
                                {
                                    int RTCode = (int)HttpAuthErrorCode.ServerProgressError;
                                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                                    return HttpReply;
                                }
                                else
                                {
                                    HttpReply = this.ReplyCCREQPLY(_userName, _deviceType, ccredreq);
                                    return HttpReply;
                                }
                            }
                        }
                    }
                }

            }
        }


        private HttpTrx ReplyCCREQPLY(string username, string devicetype, CCREDREQ ccredreq)
        {
            HttpTrx HttpReply = new HttpTrx();
            CCREDPLY CCredReply = new CCREDPLY();
            string _replyProcessStep = ProcessStep.CRED_PLY.ToString();

            try
            {
                string CredentialStr = this.GenerateCredential(username);
                if (CredentialStr == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.CreateCredentialError;
                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                    return HttpReply;
                }

                CCredReply.ServerName = Configuration["Server:ServerName"];
                CCredReply.Credential = CredentialStr;
                CCredReply.TimeStamp = DateTime.Now;

                string CCredReplyJsonStr = System.Text.Json.JsonSerializer.Serialize(CCredReply);
                AuthDES DES = new AuthDES();
                string DataContentDES = DES.EncryptDES(CCredReplyJsonStr);

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
                    HttpReply.ReturnMsg += ", Error Msg = " + ECSEncryptRetMsg;
                    return HttpReply;
                }
                else
                {
                    HttpReply = new HttpTrx();
                    HttpReply.UserName = username;
                    HttpReply.ProcStep = _replyProcessStep;
                    HttpReply.ReturnCode = 0;
                    HttpReply.ReturnMsg = string.Empty;
                    HttpReply.DataContent = DataContentDES;
                    HttpReply.ECS = ECSEncryptStr;
                    HttpReply.ECSSign = string.Empty;
                    return HttpReply;
                }
            }
            catch (Exception ex)
            {
                HttpReply = HttpReplyNG.Trx(_replyProcessStep, ex);
                return HttpReply;
            }
        }

        private string DecryptBaseDESData(string DataContent)
        {
            AuthBaseDES objDes = new AuthBaseDES();
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


        private bool Handle_CCREDREQ(string username, string devicetype, CCREDREQ ccredreq)
        {
            //---暫時 Always Return True 以後有想到邏輯再補上
            return true;
        }

        private string GenerateCredential(string username)
        {
            var credObj = ObjectManagerInstance.GetCredInfo(username);
            string credJsonStr = JsonSerializer.Serialize(credObj);
            string signOut = string.Empty;
            string Credential = string.Empty;
            if (SecurityManager.SIGNRSASecurity().SignString(credJsonStr, out signOut, out string returnMsgOut) == 0)
            {
                Credential Credition = new Credential();
                Credition.CredContent = credJsonStr;
                Credition.CredSign = signOut;
                Credential = JsonSerializer.Serialize(Credition);
                this.ObjectManagerInstance.SetCredential(username, Credential);
            }
            else
            {
                Credential = string.Empty;
            }
            return Credential;
        }

      
    }
}
