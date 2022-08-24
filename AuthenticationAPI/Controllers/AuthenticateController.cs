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
        private readonly MetaDBContext DBcontext;

        public AuthenticateController(ILogger<LoginController> _logger, IEnumerable<IService> _services, IQueueManager _queuemanager, MetaDBContext _dbcontext, IConfiguration _configuration, ISecurityManager _securitymanager)
        {
            Logger = _logger;
            Services = _services;
            Configuration = _configuration;
            QueueManager = _queuemanager;
            DBcontext = _dbcontext;
            SecurityManager = _securitymanager;


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
            else if (!CheckProcStepCorrect(ProcStep))
            {
                int RTCode = (int)HttpAuthErrorCode.ProcStepNotMatch;
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
            }
            else
            {
                //---- Reply Information -----
                HttpReply = new HttpTrx();
                CCREDPLY CCredReply = new CCREDPLY();
                try
                {
                    //------ Assemble ------
                    CCredReply.ServerName =  Configuration["Server:ServerName"];
                    CCredReply.Credential = this.GetCredential(UserName);
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
                    }
                }
                catch (Exception ex)
                {
                    HttpReply = this.ReplyNGHttpTrx(ReplyProcStep, ex);
                }
            }
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
                SecurityManager.GetRSASecurity(UserName, DeviceType).setClientID = UserName;
                SecurityManager.GetRSASecurity(UserName, DeviceType).setClientPublicKey = uuidrpt.MobilePublicKey;

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

        private void Do_UUID_ANN( string UserName, string UUID)
        {
            WSTrx WebSocketReply = null;
            string ReplyProcStep = ProcessStep.UUID_ANN.ToString();
            string Device_type = DeviceType.CONSOLE.ToString();

            DUUIDANN uuidann = new DUUIDANN();
            try
            {
                uuidann.ServerName = Configuration["Server:ServerName"];
                uuidann.DeviceUUID = UUID;
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
            }
            catch
            {

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


        private bool CheckProcStepCorrect(string procStep)
        {
            bool StatusCorrect = false;
            try
            {
                ProcessStep PStep = (ProcessStep)Enum.Parse(typeof(ProcessStep), procStep);
                switch (PStep)
                {
                    case ProcessStep.CRED_REQ:
                    case ProcessStep.UUID_RPT:
                    case ProcessStep.AREG_CMP:
                        StatusCorrect = true;
                        break;
                    default:
                        StatusCorrect = false;
                        break;
                }
            }
            catch
            {
                StatusCorrect = false;
            }
            return StatusCorrect;
        }

        private string ReplyProcStep(string procStep)
        {
            string ReplyProcStep = string.Empty;
            try
            {
                ProcessStep PStep = (ProcessStep)Enum.Parse(typeof(ProcessStep), procStep);
                switch (PStep)
                {
                    case ProcessStep.CRED_REQ:
                        ReplyProcStep = ProcessStep.CRED_PLY.ToString();
                        break;
                    case ProcessStep.UUID_RPT:
                        ReplyProcStep = ProcessStep.UUID_ACK.ToString();
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


        private string GetCredential(string UserName)
        {

            return "Abce123";

        }

        private string GetDeviceUUID(string UserName)
        {

            return "Abce123";

        }

        private void SetDeviceUUID(string UserName, string UUID)
        {


        }


        private void SetDeviceRegFinish(string UserName)
        {


        }



        private void testing()
        {

         

        }

    }
}
