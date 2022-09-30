using AuthenticationAPI.DtoS;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthenticationAPI.Service
{
    public class CRUIDRPTService : IHttpTrxService
    {
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public CRUIDRPTService(ILogger<CRUIDRPTService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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
                return TransService.CRUIDRPT.ToString();
            }
        }
        public HttpTrx HandlepHttpTrx(HttpTrx Msg)
        {
            HttpTrx HttpReply = null;
            string replyProcessStep = ProcessStep.CRUIDPLY.ToString();
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
                string DecrypStr = this.DecryptBaseDES(Msg.datacontent);
                if (DecrypStr == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.DecryptError;
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                    return HttpReply;
                }
                else
                {
                    if (!DeserializeObj.TryParseJson(DecrypStr, out CRUIDRPT cruidrpt))
                    {
                        int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                        HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                        return HttpReply;
                    }
                    else
                    {
                        if (Handle_CRUIDRPT(userName, deviceType, cruidrpt) == false)
                        {
                            int RTCode = (int)HttpAuthErrorCode.ServiceProgressError;
                            HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                            return HttpReply;
                        }
                        else
                        {
                            HttpReply = ReplyCRUIDACK(userName, deviceType, cruidrpt);
                            return HttpReply;
                        }
                    }
                }
            }
        }

        private string DecryptBaseDES(string DataContent)
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


        private bool Handle_CRUIDRPT(string username, string devicetype, CRUIDRPT cruidrpt)
        {
            bool result = false;
            try
            {
                UpdateSecurityManager(username, devicetype, cruidrpt.MobilePublicKey);
                SetUIDInfo(username, cruidrpt.DeviceUUIDJSon);
                result = true;
            }
            catch (Exception ex)
            {
                result = false;
                Logger.LogError("Handle CRUIDRPT Error, Msg = " + ex.Message);
            }
            return result;
        }
        private void UpdateSecurityManager(string username, string devicetype, string MobilePublicKey)
        {
            try
            {
                SecurityManager.GetRSASecurity(username, devicetype).ClientID = username;
                SecurityManager.GetRSASecurity(username, devicetype).ClientPublicKey = MobilePublicKey;
                SecurityManager.UpdateAuthSecurityToDB(username, devicetype);
            }
            catch (Exception ex)
            {
                throw new Exception("Update Security Manager Error, Msg = " + ex.Message);
            }
        }
        private void SetUIDInfo(string username, string DeviceUUIDJSon)
        {
            try
            {
                var objCredential = ObjectManagerInstance.GetCredInfo(username);
                objCredential.DeviceUUID = DeviceUUIDJSon;
                ObjectManagerInstance.SetCredInfo(username, objCredential);
            }
            catch (Exception ex)
            {
                throw new Exception("Set UID Info to Object Manager Error, Msg = " + ex.Message);
            }
        }
        private HttpTrx ReplyCRUIDACK(string username, string devicetype, CRUIDRPT duuidrt)
        {
            HttpTrx HttpReply = new HttpTrx();
            CRUIDPLY uuidack = new CRUIDPLY();
            string replyProcessStep = ProcessStep.CRUIDPLY.ToString();
            try
            {
                uuidack.ServerName = Configuration["Server:ServerName"];
                uuidack.ServerPublicKey = SecurityManager.GetRSASecurity(username, devicetype).PublicKey;
 
                string UUIDReplyJsonStr = System.Text.Json.JsonSerializer.Serialize(uuidack);
                AuthDES DES = new AuthDES();
                string DataContentDES = DES.EncryptDES(UUIDReplyJsonStr);

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
                }
            }
            catch (Exception ex)
            {
                HttpReply = HttpReplyNG.Trx(replyProcessStep, ex);
            }
            return HttpReply;
        }
    }
}
