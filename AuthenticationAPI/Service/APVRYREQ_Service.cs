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
    public class APVRYREQ_Service : IHttpTrxService
    {
        private string _SeviceName = "APVRYREQ";
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public APVRYREQ_Service(ILogger<APREGCMP_Service> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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

            string _replyProcessStep = ProcessStep.AVRY_PLY.ToString();
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
                            APVRYREQ apvryreq = DeserializeObj._APVRYREQ(DecrypContent);
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
                                    HttpReply = this.ReplyAPVRYPLY(_userName, _deviceType, apvryreq);
                                    return HttpReply;
                                }
                            }
                        }
                    }
                }
            }
        }

        private HttpTrx ReplyAPVRYPLY(string username, string devicetype, APVRYREQ apvryreq)
        {
            HttpTrx HttpReply = null;
            APVRYPLY Vryply = new APVRYPLY();
            string _replyProcessStep = ProcessStep.AVRY_PLY.ToString();

            try
            {
                Vryply.HashPassword = GetHashPassWord(username);
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

        private bool Handle_APVRYREQ(string username, string devicetype, APVRYREQ apvryreq)
        {
            
            return true;
        }

        private string GetHashPassWord(string username)
        {
            return "Abcde";
        }
    }
}
