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
    public class APVRYCMP_Service : IHttpTrxService
    {
        private string _SeviceName = "APVRYCMP";
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public APVRYCMP_Service(ILogger<APREGCMP_Service> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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

            string _replyProcessStep = ProcessStep.AVRY_FIN.ToString();
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
                            APVRYCMP apvrycmp = DeserializeObj._APVRYCMP(DecrypContent);
                            if (apvrycmp == null)
                            {
                                int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                                HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                                return HttpReply;
                            }
                            else
                            {
                                if (Handle_APVRYCMP(_userName, _deviceType, apvrycmp) == false)
                                {
                                    int RTCode = (int)HttpAuthErrorCode.ServerProgressError;
                                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                                    return HttpReply;
                                }
                                else
                                {
                                    HttpReply = this.ReplyAPVRYFIN(_userName, _deviceType, apvrycmp);
                                    return HttpReply;
                                }
                            }
                        }
                    }
                }
            }
        }

        private HttpTrx ReplyAPVRYFIN(string username, string devicetype, APVRYCMP apvrycmp)
        {
            HttpTrx HttpReply = new HttpTrx();
            string _replyProcessStep = ProcessStep.AVRY_FIN.ToString();
            try
            {
                HttpReply = new HttpTrx();
                HttpReply.username = username;
                HttpReply.procstep = _replyProcessStep;
                HttpReply.returncode = 0;
                HttpReply.returnmsg = string.Empty;
                HttpReply.datacontent = string.Empty;
                HttpReply.ecs = string.Empty;
                HttpReply.ecssign = string.Empty;
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

        private bool Handle_APVRYCMP(string username, string devicetype, APVRYCMP apregcmp)
        {
            //---暫時 Always Return True 以後有想到邏輯再補上
            return true;
        }
    }
}
