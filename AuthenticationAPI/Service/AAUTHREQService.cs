using AuthenticationAPI.Authenticate;
using AuthenticationAPI.DtoS;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Security;
using AuthenticationAPI.Structure;
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
    public class AAUTHREQService : IHttpTrxService
    {
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private readonly IEnumerable<IAuthenticate> Authenticates;
        private ObjectManager ObjectManagerInstance = null;
        public AAUTHREQService(ILogger<ARREGCMPService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager, IEnumerable<IAuthenticate> authenticates)
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
                return TransService.AAUTHREQ.ToString();
            }
        }

        public HttpTrx HandlepHttpTrx(HttpTrx Msg)
        {
            HttpTrx HttpReply = null;
            string replyProcessStep = ProcessStep.AAUTHPLY.ToString();
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
                            if (!DeserializeObj.TryParseJson(DecrypContent, out AAUTHREQ aauthreq))
                            {
                                int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                                HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                                return HttpReply;
                            }
                            else
                            {
                                if (CheckPassWordCode(userName, aauthreq.PassWord, aauthreq.PassCode, out string returnMsg) == false)
                                {
                                    int RTCode = (int)HttpAuthErrorCode.CheckDeviceInfoFail;
                                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode, returnMsg);
                                    return HttpReply;
                                }
                                else
                                {
                                    if (Handle_APVRYREQ(userName, deviceType, aauthreq) == false)
                                    {
                                        int RTCode = (int)HttpAuthErrorCode.ServiceProgressError;
                                        HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                                        return HttpReply;
                                    }
                                    else
                                    {
                                        HttpReply = ReplyAPVRYPLY(userName, deviceType, aauthreq);
                                        return HttpReply;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        private bool CheckPassWordCode(string username, string password, string passcode, out string RetMsg)
        {
            RetMsg = string.Empty;
            var UserPassword_Auth = Authenticates.Where(a => a.AuthenticateName == AuthenticateService.USERINFO.ToString()).FirstOrDefault();
            try
            {
                if (UserPassword_Auth != null)
                {
                    UserInfo userinfo = new UserInfo(username, password);
                    if( UserPassword_Auth.CheckAuth(userinfo, out RetMsg) == false)
                    {
                        Logger.LogWarning("[AAUTHREQ] User Info Authenticate Fail.");
                        RetMsg = "[AAUTHREQ] User Info Authenticate Fail.";
                        return false;
                    }
                    else
                    {
                        return CheckPassCode(username, passcode, out RetMsg);
                    }
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
                Logger.LogError("Check PassWordCode Process Exception, Msg = " + ex.Message);
                RetMsg = "Check PassWordCode Process Exception.";
                return false;
            }
        }


        private bool CheckPassCode(string username, string passcode, out string RetMsg)
        {
            bool result = false;
            RetMsg = string.Empty;
            PassCode_Info passcode_info = this.ObjectManagerInstance.GetPassCode(username);
            if (passcode_info == null)
            {
                RetMsg = "Error !!, Not Find Regist Pass Code.";
                result = false;
            }
            else
            {
                if(passcode_info.PassCode != passcode)
                {
                    RetMsg = "Error !!, PassCode Mismatch.";
                    result = false;
                }
                else
                {
                    if((DateTime.Now - passcode_info.CreateDateTime).TotalMinutes > 10)
                    {
                        RetMsg = "Error !!, PassCode Check Over Expire Time 10 Minute.";
                        result = false;
                    }
                    else
                    {
                        RetMsg = string.Empty;
                        result = true;
                    }
                }
            }
            return result;
        }

        private int GetRandom()
        {
            Random Rng = new Random((int)DateTime.Now.Millisecond);
            int R = Rng.Next(1, 255);
            return R;
        }

        private bool CreateSerialNoCode(string username)
        {
            bool result = false;
            try
            {
                SerialNo_Info serialNo = new SerialNo_Info();
                serialNo.SerialNo = GetRandom().ToString();
                ObjectManagerInstance.SetSerialNo(username, serialNo);
                result = true;
            }
            catch (Exception ex)
            {
                Logger.LogError(string.Format("CreateSerialNoCode Exception Error, UserName = {0}, Msg = {1}", username, ex.Message));
                result = false;
            }
            return result;
        }


        private bool Handle_APVRYREQ(string username, string devicetype, AAUTHREQ apvryreq)
        {
            //----  暫時只考慮是否正確產生 Serial Number 以後有想到什麼邏輯再補上
            return CreateSerialNoCode(username); ;
        }


        private HttpTrx ReplyAPVRYPLY(string username, string devicetype, AAUTHREQ apvryreq)
        {
            HttpTrx HttpReply = null;
            AAUTHPLY Vryply = null;
            string replyProcessStep = ProcessStep.AAUTHPLY.ToString();
            try
            {
                SerialNo_Info serialNo = this.ObjectManagerInstance.GetSerialNo(username);
                if (serialNo == null)
                {
                    int RTCode = (int)HttpAuthErrorCode.CreateSerialNoError;
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                    return HttpReply;
                }

                Vryply = new AAUTHPLY();
                Vryply.SerialNumber = GetSerialNo();

                string APVRYPLYJsonStr = System.Text.Json.JsonSerializer.Serialize(Vryply);
                AuthDES DES = new AuthDES();
                string DataContentDES = DES.EncryptDES(APVRYPLYJsonStr);

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

      
        private string GetSerialNo()
        {
            Random Rng = new Random((int)DateTime.Now.Millisecond);
            int R = Rng.Next(1, 255);
            return R.ToString();
        }

        private string GenerateHashPassWord(string username)
        {
            Random Rng = new Random((int)DateTime.Now.Millisecond);
            int R = Rng.Next(1, 255);
            Credential_Info cred = ObjectManagerInstance.GetCredInfo(username);
            cred.Nonce = R;
            string credJson = JsonSerializer.Serialize(cred);
            string SHAHW = Get_SHA1_Hash(credJson);
            return SHAHW.Substring(8);
        }

        private  string Get_SHA1_Hash(string value)
        {
            using var hash = SHA1.Create();
            var byteArray = hash.ComputeHash(Encoding.UTF8.GetBytes(value));
            return Convert.ToHexString(byteArray).ToLower();
        }
       
    }
}
