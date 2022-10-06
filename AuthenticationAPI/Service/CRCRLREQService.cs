using AuthenticationAPI.DtoS;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Text.Json;


namespace AuthenticationAPI.Service
{
    public class CRCRLREQService : IHttpTrxService
    {
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public CRCRLREQService(ILogger<CRCRLREQService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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
                return TransService.CRCRLREQ.ToString();
            }
        }

        public HttpTrx HandlepHttpTrx(HttpTrx Msg)
        {
            HttpTrx HttpReply = null;
            string replyProcessStep = ProcessStep.CRCRLPLY.ToString();
            string userName = Msg.username;
            string deviceType = Msg.devicetype;

            if (userName == string.Empty)
            {
                int RTCode = (int)HttpAuthErrorCode.UserNotExist;
                HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                return HttpReply;
            }
            else
            {
                int ReturnCode = SecurityManager.GetRSASecurity(userName, deviceType).Decrypt_Check(Msg.ecs, Msg.ecssign, out string DecryptECS, out string ReturnMsg);
                if (ReturnCode != 0)
                {
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, ReturnCode, ReturnMsg);
                    return HttpReply;
                }
                else
                {
                    if (!DeserializeObj.TryParseJson(DecryptECS, out ECS HESC))
                    {
                        int RTCode = (int)HttpAuthErrorCode.DecryptECSError;
                        HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                        return HttpReply;
                    }
                    else
                    {
                        if (HESC.Algo != "DES")
                        {
                            int RTCode = (int)HttpAuthErrorCode.DecryptError;
                            HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                            return HttpReply;
                        }
                        else
                        {
                            //--- Get Credential No Content So check Format 正確即可 ----
                            if (Handle_CCREDREQ(userName, deviceType) == false)
                            {
                                int RTCode = (int)HttpAuthErrorCode.ServiceProgressError;
                                HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                                return HttpReply;
                            }
                            else
                            {
                                HttpReply = ReplyCRCRLPLY(userName, deviceType);
                                return HttpReply;
                            }
                        }
                    }
                }
            }
        }

        private bool Handle_CCREDREQ(string username, string devicetype)
        {
            //----  暫時只考慮是否正確產生 Credential 以後有想到什麼邏輯再補上
            return GenerateCredential(username);
        }

        private HttpTrx ReplyCRCRLPLY(string username, string devicetype)
        {
            HttpTrx HttpReply = new HttpTrx();
            CRCRLPLY CCredReply = null;
            string replyProcessStep = ProcessStep.CRCRLPLY.ToString();
            try
            {
                string cardSign = this.ObjectManagerInstance.GetCredentialSign(username);
                if (cardSign == null)
                {
                    int RTCode = (int)HttpAuthErrorCode.CreateCredentialError;
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                    return HttpReply;
                }

                CCredReply = new CRCRLPLY();
                CCredReply.CredentialSign = cardSign.Substring(0,8);   // Base on BLE Limit Send Credential Sign 8 Char
                
                string CCredReplyJsonStr = System.Text.Json.JsonSerializer.Serialize(CCredReply);
                AuthDES DES = new AuthDES();
                string DataContentDES = DES.EncryptDES(CCredReplyJsonStr);

                ECS HESC = new ECS();
                HESC.Algo = "DES";
                HESC.Key = DES.GetKey();
                HESC.IV = DES.GetIV();

                string HESCJsonStr = JsonSerializer.Serialize(HESC);
                string ECSEncryptStr = SecurityManager.EncryptByClientPublicKey(username, devicetype, HESCJsonStr, out string ECSEncryptRetMsg);

                if (ECSEncryptStr == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.ECSbyPublicKeyErrorRSA;
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                    HttpReply.returnmsg += ", Error Msg = " + ECSEncryptRetMsg;
                    return HttpReply;
                }
                else
                {
                    HttpReply = new HttpTrx();
                    HttpReply.username = username;
                    HttpReply.procstep = replyProcessStep;
                    HttpReply.returncode = 0;
                    HttpReply.returnmsg = string.Empty;
                    HttpReply.datacontent = DataContentDES;
                    HttpReply.ecs = ECSEncryptStr;
                    HttpReply.ecssign = string.Empty;
                    return HttpReply;
                }
            }
            catch (Exception ex)
            {
                HttpReply = HttpReplyNG.Trx(replyProcessStep, ex);
                return HttpReply;
            }
        }

        private bool GenerateCredential(string username)
        {
            bool result = false;
            try
            {
                Credential_Info credObj = ObjectManagerInstance.GetCredInfo(username);
                credObj.Nonce = 0;
                string credJsonStr = JsonSerializer.Serialize(credObj);
                if (SecurityManager.SIGNRSASecurity().SignString(credJsonStr, out string signOut, out string returnMsgOut) == 0)
                {
                    //Credential Cred = new Credential();
                   // Cred.CredContent = credJsonStr;
                   // Cred.CredSign = signOut;
                    this.ObjectManagerInstance.SetCredentialSign(username, signOut);
                    result = true;
                }
                else
                {
                    Logger.LogError(string.Format("GenerateCredential Error, Sign Credential Info Error, UserName = ", username));
                    result = false;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError(string.Format("GenerateCredential Exception Error, UserName = {0}, Msg = {1}", ex.Message, username));
                result = false;
            }
            return result;
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
    }
}
