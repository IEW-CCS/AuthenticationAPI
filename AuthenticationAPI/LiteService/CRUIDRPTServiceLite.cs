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
    public class CRUIDRPTServiceLite : IHttpTrxService
    {
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public CRUIDRPTServiceLite(ILogger<CRUIDRPTService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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
                return TransServiceLite.CRUIDRPT_Lite.ToString();
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
                if (!DeserializeObj.TryParseJson(Msg.datacontent, out CRUIDRPT cruidrpt))
                {
                    int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                    return HttpReply;
                }
                else
                {

                    if (Handle_DUUIDRPT(userName, deviceType, cruidrpt) == false)
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
        private bool Handle_DUUIDRPT(string username, string devicetype, CRUIDRPT cruidrpt)
        {
            bool result = false;
            try
            {
                SetUIDInfo(username, cruidrpt.DeviceUUIDJSon);
                result = true;
            }
            catch (Exception ex)
            {
                result = false;
                Logger.LogError("Handle CRUIDRPT Report Error, Msg = " + ex.Message);
            }
            return result;

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

                HttpReply = new HttpTrx();
                HttpReply.username = username;
                HttpReply.devicetype = DeviceType.MOBILE.ToString();
                HttpReply.procstep = replyProcessStep;
                HttpReply.returncode = 0;
                HttpReply.returnmsg = string.Empty;
                HttpReply.datacontent = UUIDReplyJsonStr;
                HttpReply.ecs = string.Empty;
                HttpReply.ecssign = string.Empty;
            }
            catch (Exception ex)
            {
                HttpReply = HttpReplyNG.Trx(replyProcessStep, ex);
            }
            return HttpReply;
        }
    }
}
