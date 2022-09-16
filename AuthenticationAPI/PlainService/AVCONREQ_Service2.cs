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
    public class AVCONREQ_Service2 : IHttpTrxService
    {
        private string _SeviceName = "AVCONREQ2";
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public AVCONREQ_Service2(ILogger<APREGCMP_Service> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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

            string replyProcessStep = ProcessStep.VCON_PLY.ToString();
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
                AVCONREQ avconreq = DeserializeObj._AVCONREQ(Msg.datacontent);
                if (avconreq == null)
                {
                    int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                    return HttpReply;
                }
                else
                {
                    if (Handle_AVCONREQ(userName, deviceType, avconreq) == false)
                    {
                        int RTCode = (int)HttpAuthErrorCode.ServerProgressError;
                        HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                        return HttpReply;
                    }
                    else
                    {
                        HttpReply = this.ReplyAVCONPLY(userName, deviceType, avconreq);
                        return HttpReply;
                    }
                }
            }
        }

        private HttpTrx ReplyAVCONPLY(string username, string devicetype, AVCONREQ avconreq)
        {
            HttpTrx HttpReply = null;
            AVCONPLY VCONPLY = new AVCONPLY();
            string _replyProcessStep = ProcessStep.VCON_PLY.ToString();

            try
            {
                VCONPLY.PassCode = GetRandom().ToString();
                string AVCONPLYJsonStr = System.Text.Json.JsonSerializer.Serialize(VCONPLY);

                HttpReply = new HttpTrx();
                HttpReply.username = username;
                HttpReply.procstep = _replyProcessStep;
                HttpReply.returncode = 0;
                HttpReply.returnmsg = string.Empty;
                HttpReply.datacontent = AVCONPLYJsonStr;
                HttpReply.ecs = string.Empty;
                HttpReply.ecssign = string.Empty;
            }
            catch (Exception ex)
            {
                HttpReply = HttpReplyNG.Trx(_replyProcessStep, ex);
            }
            return HttpReply;
        }

        private bool Handle_AVCONREQ(string username, string devicetype, AVCONREQ avconreq)
        {
            return true;
        }

        private int GetRandom()
        {
            Random Rng = new Random((int)DateTime.Now.Millisecond);
            int R = Rng.Next(1, 255);
            return R;
        }
    }
}
