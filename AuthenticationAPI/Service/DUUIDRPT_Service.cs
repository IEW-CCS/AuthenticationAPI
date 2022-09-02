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
    public class DUUIDRPT_Service : IHttpTrxService
    {
        private string _SeviceName = "DUUIDRPT";

        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public DUUIDRPT_Service(ILogger<DUUIDRPT_Service> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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

            string _replyProcessStep = ProcessStep.UUID_ACK.ToString();
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
                string DecrypStr = this.DecryptBaseDESData(Msg.DataContent);
                if (DecrypStr == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.DecryptError;
                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                    return HttpReply;
                }
                else
                {
                    DUUIDRPT uuidrpt = DeserializeObj._DUUIDRPT(DecrypStr);
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
        }


        private HttpTrx ReplyDUUIDACK(string username, string devicetype, DUUIDRPT duuidrt)
        {
            HttpTrx HttpReply = new HttpTrx();
            DUUIDACK uuidack = new DUUIDACK();
            string _replyProcessStep = ProcessStep.UUID_ACK.ToString();
            try
            {
                uuidack.ServerName = Configuration["Server:ServerName"];
                uuidack.ServicePublicKey = SecurityManager.GetRSASecurity(username, devicetype).PublicKey;
                uuidack.TimeStamp = DateTime.Now;

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


        private bool Handle_DUUIDRPT(string username, string devicetype, DUUIDRPT uuidrpt)
        {
            bool result = false;

            try
            {
                SecurityManager.GetRSASecurity(username, devicetype).ClientID = username;
                SecurityManager.GetRSASecurity(username, devicetype).ClientPublicKey = uuidrpt.MobilePublicKey;
                SecurityManager.UpdateAuthSecurityToDB(username, devicetype);
                ObjectManagerInstance.SetDeviceUUID(username, uuidrpt.DeviceUUID);
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
