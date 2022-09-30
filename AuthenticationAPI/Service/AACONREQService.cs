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
    public class AACONREQService : IHttpTrxService
    {
        private string _SeviceName = TransService.AACONREQ.ToString();
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public AACONREQService(ILogger<ARREGCMPService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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
                    if (!DeserializeObj.TryParseJson(DecryptECS, out ECS HESC))
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
                            if (!DeserializeObj.TryParseJson(DecrypContent, out AACONREQ aaconreq))
                            {
                                int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                                HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                                return HttpReply;
                            }
                            else
                            {
                                if (Handle_AVCONREQ(userName, deviceType, aaconreq) == false)
                                {
                                    int RTCode = (int)HttpAuthErrorCode.ServiceProgressError;
                                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                                    return HttpReply;
                                }
                                else
                                {
                                    HttpReply = this.ReplyAVCONPLY(userName, deviceType, aaconreq);
                                    return HttpReply;
                                }
                            }
                        }
                    }
                }
            }
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
                AuthDES DES = new AuthDES();
                string DataContentDES = DES.EncryptDES(AVCONPLYJsonStr);

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
