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
    public class AACONREQServiceLite : IHttpTrxService
    {
        private string _SeviceName = TransServiceLite.AACONREQ_Lite.ToString();
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public AACONREQServiceLite(ILogger<ARREGCMPService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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

            string replyProcessStep = ProcessStep.AACONPLY.ToString();
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
                string DecryptECS = string.Empty;
                string ReturnMsg = string.Empty;
                int ReturnCode = SecurityManager.GetRSASecurity(userName, deviceType).Decrypt_Check(Msg.ecs, Msg.ecssign, out DecryptECS, out ReturnMsg);
                if (ReturnCode != 0)
                {
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, ReturnCode, ReturnMsg);
                    return HttpReply;
                }
                else
                {
                    ECS HESC = DeserializeObj._ECS(DecryptECS);
                    if (HESC == null)
                    {
                        int RTCode = (int)HttpAuthErrorCode.DecryptECSError;
                        HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                        return HttpReply;
                    }
                    else
                    {
                        string DecrypContent = this.DecryptDESData(HESC.Key, HESC.IV, Msg.datacontent);
                        if (DecrypContent == string.Empty)
                        {
                            int RTCode = (int)HttpAuthErrorCode.DecryptError;
                            HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                            return HttpReply;
                        }
                        else
                        {
                            AACONREQ avconreq = DeserializeObj._AVCONREQ(DecrypContent);
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
                }
            }
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

        private HttpTrx ReplyAVCONPLY(string username, string devicetype, AACONREQ avconreq)
        {
            HttpTrx HttpReply = null;
            AACONPLY VCONPLY = new AACONPLY();
            string _replyProcessStep = ProcessStep.AACONPLY.ToString();

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

        private bool Handle_AVCONREQ(string username, string devicetype, AACONREQ avconreq)
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
