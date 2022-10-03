using AuthenticationAPI.Authenticate;
using AuthenticationAPI.DtoS;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Security;
using AuthenticationAPI.Structure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace AuthenticationAPI.Service
{
    public class AACONREQService : IHttpTrxService
    {
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private readonly IEnumerable<IAuthenticate> Authenticates;
        private ObjectManager ObjectManagerInstance = null;

        public AACONREQService(ILogger<ARREGCMPService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager, IEnumerable<IAuthenticate> authenticates)
        {
            Logger = logger;
            Configuration = configuration;
            SecurityManager = securitymanager;
            Authenticates = authenticates;
            ObjectManagerInstance = (ObjectManager)objectmanager.GetInstance;
        }

        public string ServiceName
        {
            get
            {
                return TransService.AACONREQ.ToString();
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
                                if (CheckDeviceIDInfo(aaconreq.DeviceCode, out string returnMsg) == false)
                                {
                                    int RTCode = (int)HttpAuthErrorCode.CheckDeviceInfoFail;
                                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode, returnMsg);
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
                                        HttpReply = ReplyAVCONPLY(userName, deviceType, aaconreq);
                                        return HttpReply;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        private bool CheckDeviceIDInfo(string deviceID, out string RetMsg)
        {
            RetMsg = string.Empty;
            var DeviceCode_Auth = Authenticates.Where(a => a.AuthenticateName == AuthenticateService.DEVICEID.ToString()).FirstOrDefault();
            try
            {
                if (DeviceCode_Auth != null)
                {
                    DeviceInfo device = new DeviceInfo(deviceID);
                    return DeviceCode_Auth.CheckAuth(device, out RetMsg);
                }
                else
                {
                    Logger.LogError("USERINFO Service Not Register, so can be Handle.");
                    RetMsg = "Authenticate Service not Register.";
                    return false;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("USERINFO Process Exception, Msg = " + ex.Message);
                RetMsg = "Authenticate Service Exception.";
                return false; ;
            }
        }
        private bool Handle_AVCONREQ(string username, string devicetype, AACONREQ avconreq)
        {
            //----  暫時只考慮是否正確產生 CreatePassCode 以後有想到什麼邏輯再補上
            return CreatePassCode(username);
        }

        private HttpTrx ReplyAVCONPLY(string username, string devicetype, AACONREQ avconreq)
        {
            HttpTrx HttpReply = null;
            AACONPLY VCONPLY = null;
            string replyProcessStep = ProcessStep.AACONPLY.ToString();
            try
            {
                PassCode_Info passcode = this.ObjectManagerInstance.GetPassCode(username);
                if (passcode == null)
                {
                    int RTCode = (int)HttpAuthErrorCode.CreatePassCodeError;
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                    return HttpReply;
                }

                VCONPLY = new AACONPLY();
                VCONPLY.PassCode = passcode.PassCode;

                string AVCONPLYJsonStr = System.Text.Json.JsonSerializer.Serialize(VCONPLY);
                AuthDES DES = new AuthDES();
                string DataContentDES = DES.EncryptDES(AVCONPLYJsonStr);

                ECS HESC = new ECS();
                HESC.Algo = "DES";
                HESC.Key = DES.GetKey();
                HESC.IV = DES.GetIV();

                string HESCJsonStr = JsonSerializer.Serialize(HESC);
                string ECSEncryptStr = SecurityManager.Encrypt_Sign(username, devicetype, HESCJsonStr, out string SignStr, out string ECSEncryptRetMsg);

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
                    HttpReply.ecssign = SignStr;

                }
            }
            catch (Exception ex)
            {
                HttpReply = HttpReplyNG.Trx(replyProcessStep, ex);
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

        private bool CreatePassCode(string username)
        {
            bool result = false;
            try
            {
                PassCode_Info passcode = new PassCode_Info();
                passcode.PassCode = GetRandom().ToString();
                ObjectManagerInstance.SetPassCode(username, passcode);
                result = true;
            }
            catch (Exception ex)
            {
                Logger.LogError(string.Format("CreatePassCode Exception Error, UserName = {0}, Msg = {1}",  username, ex.Message));
                result = false;
            }
            return result;
        }

        private int GetRandom()
        {
            Random Rng = new Random((int)DateTime.Now.Millisecond);
            int R = Rng.Next(1, 255);
            return R;
        }
    }
}
