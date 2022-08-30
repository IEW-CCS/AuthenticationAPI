using AuthenticationAPI.DtoS;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Cors;
using AuthenticationAPI.DBContext;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Security;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace AuthenticationAPI.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    [EnableCors("CorsPolicy")]
    public class AuthenticateController : ControllerBase
    {
        private readonly ILogger<LoginController> Logger;
        private readonly IEnumerable<IService> Services;
        private readonly IConfiguration Configuration;
        private readonly IQueueManager QueueManager;
        private readonly ISecurityManager SecurityManager;
        private readonly IObjectManager ObjectManager;
        private readonly MetaDBContext DBcontext;

        public AuthenticateController(ILogger<LoginController> logger, IEnumerable<IService> services, IQueueManager queuemanager, MetaDBContext dbcontext, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
        {
            Logger = logger;
            Services = services;
            Configuration = configuration;
            QueueManager = queuemanager;
            DBcontext = dbcontext;
            SecurityManager = securitymanager;
            ObjectManager = objectmanager;

        }

        // GET: api/<AuthenticateController>
        [HttpGet]
        [EnableCors("CorsPolicy")]
        public IEnumerable<string> Get()
        {
            return new string[] { "value" };
        }

        // GET api/<AuthenticateController>/5
        [HttpGet("{id}")]
        [EnableCors("CorsPolicy")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/<AuthenticateController>
        [HttpPost]
        [EnableCors("CorsPolicy")]
        public HttpTrx Post([FromBody] HttpTrx Msg)
        {
            HttpTrx HttpReply = null;
            string UserName = Msg.UserName;
            string DeviceType = Msg.DeviceType;
            string ProcStep = Msg.ProcStep;
            string ReplyProcessStep = this.ReplyProcStep(ProcStep);

            if (ReplyProcessStep == ProcessStep.STEP_ERR.ToString())
            {
                int RTCode = (int)HttpAuthErrorCode.ProcStepNotMatch;
                HttpReply = this.ReplyNGHttpTrx(ReplyProcessStep, RTCode);
                return HttpReply;
            }
            else if (UserName == string.Empty)
            {
                int RTCode = (int)HttpAuthErrorCode.UserNotExist;
                HttpReply = this.ReplyNGHttpTrx(ReplyProcessStep, RTCode);
                return HttpReply;
            }
            else
            {
                int RTCode = 0;
                string DecrypStr = string.Empty;
                ProcessStep PStep = (ProcessStep)Enum.Parse(typeof(ProcessStep), ProcStep);
                try
                {
                    switch (PStep)
                    {
                        case ProcessStep.UUID_RPT:
                            DecrypStr = this.CheckBaseDESData(Msg.DataContent);
                            if (DecrypStr == string.Empty)
                            {
                                RTCode = (int)HttpAuthErrorCode.DecryptError;
                                HttpReply = this.ReplyNGHttpTrx(ReplyProcessStep, RTCode);
                            }
                            else
                            {
                                HttpReply = Do_UUID_RPT(DecrypStr, UserName, DeviceType);
                            }
                            break;

                        case ProcessStep.CRED_REQ:
                            string CREDREQ_RSADecStr = string.Empty;
                            string CREDREQ_RSAReturnMsg = string.Empty;
                            int CREDREQ_RSAReturnCode = 0;
                            CREDREQ_RSAReturnCode = SecurityManager.GetRSASecurity(UserName, DeviceType).Decrypt_Check(Msg.ECS, Msg.ECSSign, out CREDREQ_RSADecStr, out CREDREQ_RSAReturnMsg);
                            if (CREDREQ_RSAReturnCode != 0)
                            {
                                HttpReply = this.ReplyNGHttpTrx(ReplyProcessStep, CREDREQ_RSAReturnCode, CREDREQ_RSAReturnMsg);
                            }
                            else
                            {
                                ECS HESC = DeserializeObj._ECS(CREDREQ_RSADecStr);
                                if (HESC == null)
                                {
                                    RTCode = (int)HttpAuthErrorCode.DecryptECSError;
                                    HttpReply = this.ReplyNGHttpTrx(ReplyProcessStep, RTCode);
                                }
                                else
                                {
                                    DecrypStr = this.CheckDESData(HESC.Key, HESC.IV, Msg.DataContent);
                                    if (DecrypStr == string.Empty)
                                    {
                                        RTCode = (int)HttpAuthErrorCode.DecryptError;
                                        HttpReply = this.ReplyNGHttpTrx(ReplyProcessStep, RTCode);
                                    }
                                    else
                                    {
                                        HttpReply = Do_CRED_REQ(DecrypStr, UserName, DeviceType);
                                      
                                    }
                                }
                            }
                            break;

                        case ProcessStep.AREG_CMP:

                            string AREG_CMP_RSADecStr = string.Empty;
                            string AREG_CMP_ReturnMsg = string.Empty;
                            int AREG_CMP_RSAReturnCode = 0;

                            AREG_CMP_RSAReturnCode = SecurityManager.GetRSASecurity(UserName, DeviceType).Decrypt_Check(Msg.ECS, Msg.ECSSign, out AREG_CMP_RSADecStr, out AREG_CMP_ReturnMsg);
                            if (AREG_CMP_RSAReturnCode != 0)
                            {
                                HttpReply = this.ReplyNGHttpTrx(ReplyProcessStep, AREG_CMP_RSAReturnCode, AREG_CMP_ReturnMsg);
                            }
                            else
                            {
                                ECS HESC = DeserializeObj._ECS(AREG_CMP_RSADecStr);
                                if (HESC == null)
                                {
                                    RTCode = (int)HttpAuthErrorCode.DecryptECSError;
                                    HttpReply = this.ReplyNGHttpTrx(ReplyProcessStep, RTCode);
                                }
                                else
                                {
                                    DecrypStr = this.CheckDESData(HESC.Key, HESC.IV, Msg.DataContent);
                                    if (DecrypStr == string.Empty)
                                    {
                                        RTCode = (int)HttpAuthErrorCode.DecryptError;
                                        HttpReply = this.ReplyNGHttpTrx(ReplyProcessStep, RTCode);
                                    }
                                    else
                                    {
                                        HttpReply = Do_AREG_CMP(DecrypStr, UserName, DeviceType);
                                    }
                                }
                            }
                            break;

                        default:
                            RTCode = (int)HttpAuthErrorCode.ProcStepNotMatch;
                            HttpReply = this.ReplyNGHttpTrx(ReplyProcessStep, RTCode);
                            break;
                    }
                }
                catch (Exception ex)
                {
                    HttpReply = this.ReplyNGHttpTrx(ReplyProcessStep, ex);
                }
                return HttpReply;
            }
        }


        //--------  TryPaser Json File Call 法 --------
        //  if (TryParseJson(DecryptVryopeData, out clsVryope tmpVryopeData)) 
        public bool TryParseJson<T>(string data, out T result)
        {
            bool success = true;
            var settings = new Newtonsoft.Json.JsonSerializerSettings
            {
                Error = (sender, args) => { success = false; args.ErrorContext.Handled = true; },
                MissingMemberHandling = Newtonsoft.Json.MissingMemberHandling.Error
            };
            result = Newtonsoft.Json.JsonConvert.DeserializeObject<T>(data, settings);
            return success;
        }

        private HttpTrx ReplyNGHttpTrx(string processstep,int returnCode)
        {
            HttpTrx HttpReply = new HttpTrx();
            HttpReply.UserName = string.Empty;
            HttpReply.ProcStep = processstep;
            HttpReply.ReturnCode = returnCode;
            HttpReply.ReturnMsg = HttpAuthError.ErrorMsg(returnCode);
            HttpReply.DataContent = string.Empty;
            return HttpReply;
        }

        private HttpTrx ReplyNGHttpTrx(string processstep, int returnode, string returnMsg)
        {
            HttpTrx HttpReply = new HttpTrx();
            HttpReply.UserName = string.Empty;
            HttpReply.ProcStep = processstep;
            HttpReply.ReturnCode = returnode;
            HttpReply.ReturnMsg = returnMsg;
            HttpReply.DataContent = string.Empty;
            return HttpReply;
        }

        private HttpTrx ReplyNGHttpTrx(string processstep, Exception ex)
        {
            HttpTrx HttpReply = new HttpTrx();
            HttpReply.UserName = string.Empty;
            HttpReply.ProcStep = processstep;
            HttpReply.ReturnCode = 999;
            HttpReply.ReturnMsg = ex.Message;
            HttpReply.DataContent = string.Empty;
            return HttpReply;
        }

        private HttpTrx Do_UUID_RPT(string DecrypStr, string UserName, string DeviceType)
        {
            HttpTrx HttpReply = null;
            string ReplyProcStep = ProcessStep.UUID_ACK.ToString();
            DUUIDRPT uuidrpt = DeserializeObj._DUUIDRPT(DecrypStr);
            if (uuidrpt == null)
            {
                int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                HttpReply = this.ReplyNGHttpTrx(ReplyProcStep, RTCode);
            }
            else
            {
                //----  Update Information -----
                SecurityManager.GetRSASecurity(UserName, DeviceType).ClientID = UserName;
                SecurityManager.GetRSASecurity(UserName, DeviceType).ClientPublicKey = uuidrpt.MobilePublicKey;
                SecurityManager.UpdateToDB(UserName, DeviceType);
                ObjectManager.SetDeviceUUID(UserName, uuidrpt.DeviceUUID);

                HttpReply = new HttpTrx();
                DUUIDACK uuidack = new DUUIDACK();
                try
                {
                    //------ Assemble ------
                    uuidack.ServerName = Configuration["Server:ServerName"];
                    uuidack.ServicePublicKey = SecurityManager.GetRSASecurity(UserName, DeviceType).PublicKey;
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
                    string ECSEncryptStr = SecurityManager.EncryptByClientPublicKey(UserName, DeviceType, HESCJsonStr, out ECSEncryptRetMsg);

                    if (ECSEncryptStr == string.Empty)
                    {
                        int RTCode = (int)HttpAuthErrorCode.ECSbyPublicKeyErrorRSA;
                        HttpReply = this.ReplyNGHttpTrx(ReplyProcStep, RTCode);
                        HttpReply.ReturnMsg += ", Error Msg = " + ECSEncryptRetMsg;
                        return HttpReply;
                    }
                    else
                    {
                        HttpReply = new HttpTrx();
                        HttpReply.UserName = UserName;
                        HttpReply.ProcStep = ReplyProcStep;
                        HttpReply.ReturnCode = 0;
                        HttpReply.ReturnMsg = string.Empty;
                        HttpReply.DataContent = DataContentDES;
                        HttpReply.ECS = ECSEncryptStr;
                        HttpReply.ECSSign = string.Empty;
                    }
                }
                catch (Exception ex)
                {
                    HttpReply = this.ReplyNGHttpTrx(ReplyProcStep, ex);
                }
            }
            return HttpReply;
        }

        //--------  Do CRED_REQ -----
        private HttpTrx Do_CRED_REQ(string DecrypStr, string UserName, string DeviceType)
        {
            HttpTrx HttpReply = null;
            string ReplyProcStep = ProcessStep.CRED_PLY.ToString();
            CCREDREQ ccredreq = DeserializeObj._CCREDREQ(DecrypStr);
            if (ccredreq == null)
            {
                int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                HttpReply = this.ReplyNGHttpTrx(ReplyProcStep, RTCode);
                return HttpReply;
            }
            else
            {
                //---- Reply Information -----
                HttpReply = new HttpTrx();
                CCREDPLY CCredReply = new CCREDPLY();
                try
                {
                    string CredentialStr = this.GenerateCredential(UserName);
                    if (CredentialStr == string.Empty)
                    {
                        int RTCode = (int)HttpAuthErrorCode.CreateCredentialError;
                        HttpReply = this.ReplyNGHttpTrx(ReplyProcStep, RTCode);
                        return HttpReply;
                    }

                    //------ Assemble ------
                    CCredReply.ServerName =  Configuration["Server:ServerName"];
                    CCredReply.Credential = CredentialStr;
                    CCredReply.TimeStamp = DateTime.Now;

                    string CCredReplyJsonStr = System.Text.Json.JsonSerializer.Serialize(CCredReply);
                    AuthDES DES = new AuthDES();
                    string DataContentDES = DES.EncryptDES(CCredReplyJsonStr);

                    ECS HESC = new ECS();
                    HESC.Algo = "DES";
                    HESC.Key = DES.GetKey();
                    HESC.IV = DES.GetIV();

                    string ECSEncryptRetMsg = string.Empty;
                    string HESCJsonStr = JsonSerializer.Serialize(HESC);
                    string ECSEncryptStr = SecurityManager.EncryptByClientPublicKey(UserName, DeviceType, HESCJsonStr, out ECSEncryptRetMsg);

                    if (ECSEncryptStr == string.Empty)
                    {
                        int RTCode = (int)HttpAuthErrorCode.ECSbyPublicKeyErrorRSA;
                        HttpReply = this.ReplyNGHttpTrx(ReplyProcStep,RTCode);
                        HttpReply.ReturnMsg += ", Error Msg = " + ECSEncryptRetMsg;
                        return HttpReply;
                    }
                    else
                    {
                        
                        HttpReply = new HttpTrx();
                        HttpReply.UserName = UserName;
                        HttpReply.ProcStep = ReplyProcStep;
                        HttpReply.ReturnCode = 0;
                        HttpReply.ReturnMsg = string.Empty;
                        HttpReply.DataContent = DataContentDES;
                        HttpReply.ECS = ECSEncryptStr;
                        HttpReply.ECSSign = string.Empty;

                        if(Do_UUID_ANN(UserName, CredentialStr) ==false)
                        {
                            // Logger Do Ann Error .....
                        }


                        return HttpReply;
                    }
                }
                catch (Exception ex)
                {
                    HttpReply = this.ReplyNGHttpTrx(ReplyProcStep, ex);
                }
            }
            return HttpReply;
        }

       

        private bool Do_UUID_ANN( string UserName,  string Credential)
        {
            WSTrx WebSocketReply = null;
            string DeviceUUID = ObjectManager.GetDeviceUUID(UserName);
            string ReplyProcStep = ProcessStep.UUID_ANN.ToString();
            string Device_type = DeviceType.CONSOLE.ToString();

            DUUIDANN uuidann = new DUUIDANN();
            try
            {
                uuidann.ServerName = Configuration["Server:ServerName"];
                uuidann.DeviceUUID = DeviceUUID;
                uuidann.Credential = Credential;
                uuidann.TimeStamp = DateTime.Now;
                //------ Assemble ------

                string UUIDAnnJsonStr = System.Text.Json.JsonSerializer.Serialize(uuidann);
                AuthDES DES = new AuthDES();
                string DataContentDES = DES.EncryptDES(UUIDAnnJsonStr);

                ECS HESC = new ECS();
                HESC.Algo = "DES";
                HESC.Key = DES.GetKey();
                HESC.IV = DES.GetIV();

                string ECSEncryptRetMsg = string.Empty;
                string HESCJsonStr = JsonSerializer.Serialize(HESC);
                string SignStr = string.Empty;
                string ECSEncryptStr = SecurityManager.Encrypt_Sign(UserName, Device_type, HESCJsonStr, out SignStr, out ECSEncryptRetMsg);

                if (ECSEncryptStr != string.Empty && SignStr != string.Empty)
                {
                    WebSocketReply = new WSTrx();
                    WebSocketReply.DataContent = DataContentDES;
                    WebSocketReply.ProcStep = ReplyProcStep;
                    WebSocketReply.ReturnCode = 0;
                    WebSocketReply.ReturnMsg = string.Empty;
                    WebSocketReply.ECS = ECSEncryptStr;
                    WebSocketReply.ECSSign = SignStr;

                    string WSReplyJsonStr = System.Text.Json.JsonSerializer.Serialize(WebSocketReply);
                    //----------------------------------
                    MessageTrx msg = new MessageTrx();
                    msg.ClientID = UserName;
                    msg.Function = ReplyProcStep;     // 預留目前沒有功能
                    msg.Data = WSReplyJsonStr;
                    msg.TimeStamp = DateTime.Now;
                    QueueManager.PutMessage(msg);
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        private HttpTrx Do_AREG_CMP(string DecrypStr, string UserName, string DeviceType)
        {
            HttpTrx HttpReply = null;
            string ReplyProcStep = ProcessStep.AREG_FIN.ToString();
            APREGCMP apregcmp = DeserializeObj._APREGCMP(DecrypStr);
            if (apregcmp == null)
            {
                int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                HttpReply = this.ReplyNGHttpTrx(ReplyProcStep, RTCode);
            }
            else
            {
                try
                {
                    this.SetDeviceRegFinish(UserName);
                    HttpReply = new HttpTrx();
                    HttpReply.UserName = UserName;
                    HttpReply.ProcStep = ReplyProcStep;
                    HttpReply.ReturnCode = 0;
                    HttpReply.ReturnMsg = string.Empty;
                    HttpReply.DataContent = string.Empty;
                    HttpReply.ECS = string.Empty;
                    HttpReply.ECSSign = string.Empty;

                }
                catch (Exception ex)
                {
                    HttpReply = this.ReplyNGHttpTrx(ReplyProcStep, ex);
                }
            }
            return HttpReply;
        }

        private string CheckBaseDESData(string DataContent)
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

        private string CheckDESData(string key, string iv, string DataContent)
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

        private string ReplyProcStep(string procStep)
        {
            string ReplyProcStep = string.Empty;
            try
            {
                ProcessStep PStep = (ProcessStep)Enum.Parse(typeof(ProcessStep), procStep);
                switch (PStep)
                {
                    case ProcessStep.UUID_RPT:
                        ReplyProcStep = ProcessStep.UUID_ACK.ToString();
                        break;
                    case ProcessStep.CRED_REQ:
                        ReplyProcStep = ProcessStep.CRED_PLY.ToString();
                        break;
                    case ProcessStep.AREG_CMP:
                        ReplyProcStep = ProcessStep.AREG_FIN.ToString();
                        break;
                    default:
                        ReplyProcStep = ProcessStep.STEP_ERR.ToString();
                        break;
                }
            }
            catch
            {
                ReplyProcStep = ProcessStep.STEP_ERR.ToString();
            }
            return ReplyProcStep ;
        }


        private string GenerateCredential(string UserName)
        {
            var credObj = ObjectManager.GetCredInfo(UserName);
            string credJsonStr = JsonSerializer.Serialize(credObj);
            string signOut = string.Empty;
            string returnMsg = string.Empty;

            if(SecurityManager.SIGNRSASecurity().SignString(credJsonStr, out signOut, out returnMsg) == 0)
            {
                Credential Credition = new Credential();
                Credition.CredContent = credJsonStr;
                Credition.CredSign = signOut;
                return JsonSerializer.Serialize(Credition);
            }
            else
            {
                return string.Empty;
            }
        }

        private void SetDeviceRegFinish(string UserName)
        {
            ObjectManager.SetRegisterStatus(UserName, true);
        }

        private void UpdateCredInfo(string name, string deviceUUID)
        {
            var cred = ObjectManager.GetCredInfo(name);
            cred.DeviceUUID = deviceUUID;
            ObjectManager.SetCredInfo(name, cred);
        }
    }
}
