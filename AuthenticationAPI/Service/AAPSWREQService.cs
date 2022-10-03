using AuthenticationAPI.DtoS;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using AuthenticationAPI.Structure;

namespace AuthenticationAPI.Service
{
    public class AAPSWREQService : IHttpTrxService
    {
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public AAPSWREQService(ILogger<ARREGCMPService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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
                return TransService.AAPSWREQ.ToString();
            }
        }

        public HttpTrx HandlepHttpTrx(HttpTrx Msg)
        {
            HttpTrx HttpReply = null;
            string replyProcessStep = ProcessStep.AAPSWPLY.ToString();
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
                            if (!DeserializeObj.TryParseJson(DecrypContent, out AAPSWREQ aapswreq))
                            {
                                int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                                HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                                return HttpReply;
                            }
                            else
                            {
                                if (CheckAuthenticationInfo(userName, aapswreq, out string returnMsg) == false)
                                {
                                    int RTCode = (int)HttpAuthErrorCode.CheckAuthenticationInfoError;
                                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode, returnMsg);
                                    return HttpReply;
                                }
                                else
                                {
                                    if (Handle_APHPWREQ(userName, deviceType, aapswreq) == false)
                                    {
                                        int RTCode = (int)HttpAuthErrorCode.ServiceProgressError;
                                        HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                                        return HttpReply;
                                    }
                                    else
                                    {
                                        HttpReply = ReplyAAPSWPLY(userName, deviceType, aapswreq);
                                        return HttpReply;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }


        private bool CheckAuthenticationInfo(string username, AAPSWREQ aapswreq, out string RetMsg)
        {
            RetMsg = string.Empty;
            try
            {
                if (aapswreq.BiometricsResult == "OK")
                {
                    if (CheckSerialNo( username, aapswreq.SerialNo, out  RetMsg) == true)
                    {
                        if(CheckCredentialSign(username, aapswreq.CredentialSign, out  RetMsg) == true)
                        {
                            RetMsg = string.Empty;
                            return true;
                        }
                        else
                        {
                            Logger.LogWarning(string.Format("[AAPSWREQ] Authenticate Fail, Msg = {0}.", RetMsg));
                            RetMsg = string.Format("[AAPSWREQ] Authenticate Fail, Msg = {0}.", RetMsg);
                            return false;
                        }
                    }
                    else
                    {
                        Logger.LogWarning(string.Format("[AAPSWREQ] Authenticate Fail, Msg = {0}.", RetMsg));
                        RetMsg = string.Format("[AAPSWREQ] Authenticate Fail, Msg = {0}.", RetMsg);
                        return false;
                    }
                }
                else
                {
                    Logger.LogWarning(string.Format("[AAPSWREQ] User Reply Biometrics Result = {0} Not OK, so can be Handle.", aapswreq.BiometricsResult));
                    RetMsg = string.Format("[AAPSWREQ] User Reply Biometrics Result = {0} Not OK, so can be Handle.", aapswreq.BiometricsResult);
                    return false;
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("[AAPSWREQ] Check Authentication Info Process Exception, Msg = " + ex.Message);
                RetMsg = "[AAPSWREQ] Check Authentication Info Process Exception.";
                return false;
            }
        }

        private bool CheckSerialNo(string username, string serialnumber, out string RetMsg)
        {
            bool result = false;
            RetMsg = string.Empty;
            SerialNo_Info serialNo = this.ObjectManagerInstance.GetSerialNo(username);
            if (serialNo == null)
            {
                RetMsg = "Error !!, Not Find Regist Serial Numner.";
                result = false;
            }
            else
            {
                if (serialNo.SerialNo != serialnumber)
                {
                    RetMsg = "Error !!, Serial Number Mismatch.";
                    result = false;
                }
                else
                {
                    if ((DateTime.Now - serialNo.CreateDateTime).TotalMinutes > 10)
                    {
                        RetMsg = "Error !!, Serial Numner Check Over Expire Time 10 Minute.";
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

        private bool CheckCredentialSign(string userName, string CredentialSign, out string RetMsg)
        {
            bool result = false;
            RetMsg = string.Empty;
            Credential card = this.ObjectManagerInstance.GetCredential(userName);
            if (card == null)
            {
                RetMsg = "Error !!, Not Find Regist Credential Information.";
                result = false;
            }
            else
            {
                if (card.CredSign.Substring(0, 8) != CredentialSign)
                {
                    RetMsg = "Error !!, Credential Information Mismatch.";
                    result = false;
                }
                else
                { 
                    RetMsg = string.Empty;
                    result = true;
                }
            }
            return result;
        }


        private bool Handle_APHPWREQ(string username, string devicetype, AAPSWREQ aphpwreq)
        {
            //----  暫時只考慮是否正確產生 Serial Number 以後有想到什麼邏輯再補上
            return GenerateHashPassWord(username); ;
        }



        //---- Re modify 
        private HttpTrx ReplyAAPSWPLY(string username, string devicetype, AAPSWREQ aphpwreq)
        {
            HttpTrx HttpReply = null;
            string replyProcessStep = ProcessStep.AAPSWPLY.ToString();
            try
            {
                string hashPassword =  this.ObjectManagerInstance.GetHashPassword(username);
                if (hashPassword == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.HashPasswordCreateError;
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                    return HttpReply;
                }
                else
                {
                    AAPSWPLY aphpwply = new AAPSWPLY();
                    aphpwply.PassWordData = hashPassword;

                    string APHPWPLYJsonStr = System.Text.Json.JsonSerializer.Serialize(aphpwply);
                    AuthDES DES = new AuthDES();
                    string DataContentDES = DES.EncryptDES(APHPWPLYJsonStr);

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

   

        private bool GenerateHashPassWord(string username)
        {
            bool result = false;
            string credJson = string.Empty;
            try
            {
                Random Rng = new Random((int)DateTime.Now.Millisecond);
                int R = Rng.Next(1, 255);
                Credential_Info cred = ObjectManagerInstance.GetCredInfo(username);
                cred.Nonce = R;
                credJson = JsonSerializer.Serialize(cred);
                string SHAHW = Get_SHA1_Hash(cred);
                ObjectManagerInstance.SetHashPassword(username, SHAHW);
                result = true;
            }
            catch(Exception ex)
            {
                result = false;
                Logger.LogError(string.Format("Generate Hash Password of User = {0}, Credential = {1}, Exception Msg = {2}.", username, credJson, ex.Message));
            }
            return result;
        }


        private string Get_SHA1_Hash(string value)
        {
            using var hash = SHA1.Create();
            var byteArray = hash.ComputeHash(Encoding.UTF8.GetBytes(value));
            return Convert.ToHexString(byteArray).ToLower();
        }

        private string Get_SHA1_Hash(object value)
        {
            using var hash = SHA1.Create();
            var byteArray = hash.ComputeHash(ObjectToByteArray(value));
            return Convert.ToHexString(byteArray).ToLower();
        }

     
        private byte[] ObjectToByteArray(object obj)
        {
            if (obj == null)
                return null;
            BinaryFormatter bf = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream())
            {
                bf.Serialize(ms, obj);
                return ms.ToArray();
            }
        }
    }
}
