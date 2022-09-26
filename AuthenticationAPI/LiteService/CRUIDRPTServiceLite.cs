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
        private string _SeviceName = TransServiceLite.CRUIDRPT_Lite.ToString();

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
                return this._SeviceName;
            }
        }
        public HttpTrx HandlepHttpTrx(HttpTrx Msg)
        {

            HttpTrx HttpReply = null;

            string _replyProcessStep = ProcessStep.CRUIDPLY.ToString();
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
                CRUIDRPT uuidrpt = DeserializeObj._DUUIDRPT(Msg.datacontent);
                if (uuidrpt == null)
                {
                    int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                    return HttpReply;
                }
                else
                {

                    if (Handle_DUUIDRPT(_userName, _deviceType, uuidrpt) == false)
                    {
                        int RTCode = (int)HttpAuthErrorCode.ServerProgressError;
                        HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                        return HttpReply;
                    }
                    else
                    {
                        HttpReply = this.ReplyDUUIDACK(_userName, _deviceType, uuidrpt);
                        return HttpReply;
                    }
                }
            }
        }


        private HttpTrx ReplyDUUIDACK(string username, string devicetype, CRUIDRPT duuidrt)
        {
            HttpTrx HttpReply = new HttpTrx();
            CRUIDPLY uuidack = new CRUIDPLY();
            string _replyProcessStep = ProcessStep.CRUIDPLY.ToString();
            try
            {
                uuidack.ServerName = Configuration["Server:ServerName"];
                uuidack.ServerPublicKey = SecurityManager.GetRSASecurity(username, devicetype).PublicKey;
                string UUIDReplyJsonStr = System.Text.Json.JsonSerializer.Serialize(uuidack);

                HttpReply = new HttpTrx();
                HttpReply.username = username;
                HttpReply.devicetype = DeviceType.MOBILE.ToString();
                HttpReply.procstep = _replyProcessStep;
                HttpReply.returncode = 0;
                HttpReply.returnmsg = string.Empty;
                HttpReply.datacontent = UUIDReplyJsonStr;
                HttpReply.ecs = string.Empty;
                HttpReply.ecssign = string.Empty;
            }
            catch (Exception ex)
            {
                HttpReply = HttpReplyNG.Trx(_replyProcessStep, ex);
            }
            return HttpReply;
        }

       
        private bool Handle_DUUIDRPT(string username, string devicetype, CRUIDRPT uuidrpt)
        {
            bool result = false;
            try
            {
                var objCredential = ObjectManagerInstance.GetCredInfo(username);
                objCredential.DeviceUUID = uuidrpt.DeviceUUIDJSon;
                ObjectManagerInstance.SetCredInfo(username, objCredential);
                result = true;
            }
            catch (Exception ex)
            {
                result = false;
                Logger.LogError("Handle DUUID Report Error, Msg = " + ex.Message);
            }
            return result;

        }
    }
}
