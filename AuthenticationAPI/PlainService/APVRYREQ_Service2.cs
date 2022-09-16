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
    public class APVRYREQ_Service2 : IHttpTrxService
    {
        private string _SeviceName = "APVRYREQ2";
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public APVRYREQ_Service2(ILogger<APREGCMP_Service> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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
                APVRYREQ apvryreq = DeserializeObj._APVRYREQ(Msg.datacontent);
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
                        HttpReply = ReplyAPVRYPLY(_userName, _deviceType, apvryreq);
                        return HttpReply;
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
                Vryply.SerialNo = GetSerialNo();
                string APVRYPLYJsonStr = System.Text.Json.JsonSerializer.Serialize(Vryply);

                HttpReply = new HttpTrx();
                HttpReply.username = username;
                HttpReply.procstep = _replyProcessStep;
                HttpReply.returncode = 0;
                HttpReply.returnmsg = string.Empty;
                HttpReply.datacontent = APVRYPLYJsonStr;
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

        private bool Handle_APVRYREQ(string username, string devicetype, APVRYREQ apvryreq)
        {
            
            // --- Check PassWord and Pass Code ----

            return true;
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
            CRED_INFO cred = ObjectManagerInstance.GetCredInfo(username);
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


        private string GetHashPassWord(string username)
        {
            string hashPassword = GenerateHashPassWord(username);
            ObjectManagerInstance.SetHashPassword(username, hashPassword);
            return hashPassword;
        }
    }
}
