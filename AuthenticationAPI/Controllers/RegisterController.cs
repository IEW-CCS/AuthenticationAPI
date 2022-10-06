using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.Cors;
using AuthenticationAPI.DBContext;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Security;
using AuthenticationAPI.Service;
using AuthenticationAPI.DtoS;
using Microsoft.AspNetCore.Authorization;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace AuthenticationAPI.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    [EnableCors("CorsPolicy")]
    [Authorize(Roles = "Admin, Administrator, Register")]
    public class RegisterController : ControllerBase
    {
        private readonly ILogger Logger;
        private readonly IEnumerable<IHttpTrxService> HttpTrxServices;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private readonly IQueueManager QueueManager;
        private readonly ObjectManager ObjectManagerInstance;

        public RegisterController(ILogger<RegisterController> logger, IEnumerable<IHttpTrxService> services, IQueueManager queuemanager, IObjectManager objectmanager, IConfiguration configuration, ISecurityManager securitymanager)
        {
            Logger = logger;
            HttpTrxServices = services;
            Configuration = configuration;
            SecurityManager = securitymanager;
            QueueManager = queuemanager;
            ObjectManagerInstance = (ObjectManager) objectmanager.GetInstance;
        }

        // POST api/<AuthenticateController>
        [HttpPost]
        [EnableCors("CorsPolicy")]
        public HttpTrx Post([FromBody] HttpTrx Msg)
        {
            HttpTrx HttpReply = null;
            string UserName = Msg.username;
            string DeviceType = Msg.devicetype;
            string ProcStep = Msg.procstep;

            if (CheckProcStep(UserName, ProcStep) == false)
            {
                string ReplyProcessStep = ProcessStep.STEP_ERR.ToString();
                int RTCode = (int)HttpAuthErrorCode.ProcStepNotMatch;
                HttpReply = HttpReplyNG.Trx(ReplyProcessStep, RTCode);
                return HttpReply;
            }
            else
            {
                ProcessStep PStep = (ProcessStep)Enum.Parse(typeof(ProcessStep), ProcStep);
                try
                {
                    switch (PStep)
                    {
                        case ProcessStep.CRUIDRPT:
                            {
                                // With 104-2 Mobile App Uset Lite Service no Encrypy
                                var HandleDUUIDRPT = HttpTrxServices.Where(s => s.ServiceName == TransServiceLite.CRUIDRPT_Lite.ToString()).FirstOrDefault();
                                if (HandleDUUIDRPT != null)
                                {
                                    ObjectManagerInstance.SetRegisterStatus(UserName, ProcStep);
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation(String.Format("[Register] Service Request, User ={0}, DeviceType = {1}, ProcessStep = {2}, RawData = {3}.", Msg.username, Msg.devicetype, Msg.procstep, httpTrxMsg));
                                    HttpReply = HandleDUUIDRPT.HandlepHttpTrx(Msg);
                                    if (HttpReply.returncode == 0)
                                    {
                                        ObjectManagerInstance.SetRegisterStatus(UserName, HttpReply.procstep);
                                    }
                                    else
                                    {
                                        return HttpReply;
                                    }

                                }
                                else
                                {
                                    Logger.LogError("CRUIDRPT Service Not Register, so can be Handle.");
                                    string ReplyProcessStep = ProcessStep.CRUIDPLY.ToString();
                                    int RTCode = (int)HttpAuthErrorCode.ServiceNotRegister;
                                    HttpReply = HttpReplyNG.Trx(ReplyProcessStep, RTCode);
                                }
                                break;
                            }
                        case ProcessStep.CRCRLREQ:
                            {
                                // With 104-2 Mobile App Uset Lite Service no Encrypy
                                var HandleCREDREQ = HttpTrxServices.Where(s => s.ServiceName == TransServiceLite.CRCRLREQ_Lite.ToString()).FirstOrDefault();
                                if (HandleCREDREQ != null)
                                {
                                    ObjectManagerInstance.SetRegisterStatus(UserName, ProcStep);
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation(String.Format("[Register] Service Request, User ={0}, DeviceType = {1}, ProcessStep = {2}, RawData = {3}.", Msg.username, Msg.devicetype, Msg.procstep, httpTrxMsg));
                                    HttpReply = HandleCREDREQ.HandlepHttpTrx(Msg);
                                    if (HttpReply.returncode == 0)
                                    {
                                        ObjectManagerInstance.SetRegisterStatus(UserName, HttpReply.procstep);

                                        //---- Credential Reply OK trigger WebSocker Announce to 104-1
                                        Credential_Info  CredInfo = ObjectManagerInstance.GetCredInfo(UserName);
                                        string CredSign = ObjectManagerInstance.GetCredentialSign(UserName);
                                        if (CredSign != null && CredInfo != null)
                                        {
                                            WebSocketUIDAnnounce(UserName, CredSign, CredInfo);
                                        }
                                        else
                                        {
                                            Logger.LogError(string.Format("User = {0}, Credential Information is Empty , So Skip Handle.", UserName));
                                        }
                                    }
                                    else
                                    {
                                        return HttpReply;
                                    }
                                }
                                else
                                {
                                    Logger.LogError("CRCRLREQ Service Not Register, so can be Handle.");
                                    string ReplyProcessStep = ProcessStep.CRCRLPLY.ToString();
                                    int RTCode = (int)HttpAuthErrorCode.ServiceNotRegister;
                                    HttpReply = HttpReplyNG.Trx(ReplyProcessStep, RTCode);
                                }
                                break;
                            }
                        case ProcessStep.ARREGCMP:
                            {
                                var HandleAREGCMP = HttpTrxServices.Where(s => s.ServiceName == TransService.ARREGCMP.ToString()).FirstOrDefault();
                                if (HandleAREGCMP != null)
                                {
                                    ObjectManagerInstance.SetRegisterStatus(UserName, ProcStep);
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation(String.Format("[Register] Service Request, User ={0}, DeviceType = {1}, ProcessStep = {2}, RawData = {3}.", Msg.username, Msg.devicetype, Msg.procstep, httpTrxMsg));
                                    HttpReply = HandleAREGCMP.HandlepHttpTrx(Msg);
                                    if (HttpReply.returncode == 0)
                                    {
                                        ObjectManagerInstance.SetRegisterStatus(UserName, HttpReply.procstep);
                                    }
                                    else
                                    {
                                        return HttpReply;
                                    }
                                }
                                else
                                {
                                    Logger.LogError("ARREGCMP Service Not Register, so can be Handle.");
                                    string ReplyProcessStep = ProcessStep.ARREGFIN.ToString();
                                    int RTCode = (int)HttpAuthErrorCode.ServiceNotRegister;
                                    HttpReply = HttpReplyNG.Trx(ReplyProcessStep, RTCode);
                                }
                                break;
                            }
                        default:
                            {
                                string ReplyProcessStep = ProcessStep.STEP_ERR.ToString();
                                int RTCode = (int)HttpAuthErrorCode.ProcStepNotMatch;
                                HttpReply = HttpReplyNG.Trx(ReplyProcessStep, RTCode);
                                break;
                            }
                    }
                }
                catch (Exception ex)
                {
                    string ReplyProcessStep = ProcessStep.STEP_ERR.ToString();
                    HttpReply = HttpReplyNG.Trx(ReplyProcessStep, ex);
                }
                return HttpReply;
            }
        }
        private bool CheckProcStep(string username, string procStep)
        {
            //---------  20220930 ------
            //=========  在未來加入 Process Step Control ========
            bool result = false;
            try
            {
                ProcessStep PStep = (ProcessStep)Enum.Parse(typeof(ProcessStep), procStep);
                switch (PStep)
                {
                    case ProcessStep.CRUIDRPT:
                    case ProcessStep.CRCRLREQ:  
                    case ProcessStep.ARREGCMP:
                        result = true;
                        break;
                    default:
                        result = false;
                        break;
                }
            }
            catch
            {
                result = false;
            }
            return result;
        }



        private void WebSocketUIDAnnounce(string username, string credentialSign, Credential_Info credentialInfo)
        {
            WSTrx WebSocketReply = null;
            string replyProcStep = ProcessStep.ARWSCANN.ToString();
            string device_type = DeviceType.CONSOLE.ToString();

            try
            {
                credentialInfo.Nonce = 0;
                string credJsonStr = JsonSerializer.Serialize(credentialInfo);
                ARWSCANN wsuidann = new ARWSCANN();
                wsuidann.Credential = credJsonStr;
                wsuidann.CredentialSign = credentialSign.Substring(0, 8);  // Base on BLE Limit Send Credential Sign 8 Char
                wsuidann.SignedPublicKey = SecurityManager.SIGNRSASecurity().PublicKey;
                wsuidann.DeviceUUID = credentialInfo.DeviceUUID;
                string Datacontent = System.Text.Json.JsonSerializer.Serialize(wsuidann);

                WebSocketReply = new WSTrx();
                WebSocketReply.DataContent = Datacontent;
                WebSocketReply.ProcStep = replyProcStep;
                WebSocketReply.ReturnCode = 0;
                WebSocketReply.ReturnMsg = string.Empty;
                WebSocketReply.ECS = string.Empty;
                WebSocketReply.ECSSign = string.Empty; ;
                string WSReplyJsonStr = System.Text.Json.JsonSerializer.Serialize(WebSocketReply);
                SendWebsocket(username, string.Empty, WSReplyJsonStr);
            }
            catch (Exception ex)
            {
                Logger.LogError("WebSocket Announce UID Error, Err Msg = " + ex.Message);
            }

            /*  20220915 封存 With 加密程序
             * try
               {
                   WSUIDANN wsuidann = new WSUIDANN();
                   wsuidann.Credential = credentialcontent.CredContent;
                   wsuidann.SignedPublicKey = SecurityManager.SIGNRSASecurity().PublicKey;
                   string Datacontent = System.Text.Json.JsonSerializer.Serialize(wsuidann);

                   string UUIDAnnJsonStr = System.Text.Json.JsonSerializer.Serialize(wsuidann);
                   AuthDES DES = new AuthDES();
                   string DataContentDES = DES.EncryptDES(UUIDAnnJsonStr);

                   ECS HESC = new ECS();
                   HESC.Algo = "DES";
                   HESC.Key = DES.GetKey();
                   HESC.IV = DES.GetIV();

                   string ECSEncryptRetMsg = string.Empty;
                   string HESCJsonStr = JsonSerializer.Serialize(HESC);
                   string SignStr = string.Empty;
                   string ECSEncryptStr = SecurityManager.Encrypt_Sign(username, device_type, HESCJsonStr, out SignStr, out ECSEncryptRetMsg);

                   if (ECSEncryptStr != string.Empty && SignStr != string.Empty)
                   {
                       WebSocketReply = new WSTrx();
                       WebSocketReply.DataContent = DataContentDES;
                       WebSocketReply.ProcStep = replyProcStep;
                       WebSocketReply.ReturnCode = 0;
                       WebSocketReply.ReturnMsg = string.Empty;
                       WebSocketReply.ECS = ECSEncryptStr;
                       WebSocketReply.ECSSign = SignStr;
                       string WSReplyJsonStr = System.Text.Json.JsonSerializer.Serialize(WebSocketReply);
                       SendWebsocket(username, string.Empty, WSReplyJsonStr);
                   }
               }
               catch (Exception ex)
               {
                   Logger.LogError("UID ANN Error, Err Msg = " + ex.Message);
               }*/
        }

        private void SendWebsocket( string clientID, string Function, string datacontent)
        {
            try
            {
                MessageTrx msg = new MessageTrx();
                msg.ClientID = clientID;
                msg.Function = Function;
                msg.Data = datacontent;
                msg.TimeStamp = DateTime.Now;
                QueueManager.PutMessage(msg);
            }
            catch (Exception Ex)
            {
                Logger.LogError("Send Data via WebSocket Tunnel Error, Err Msg = " + Ex.Message);
            }
        }

        // GET: api/<AuthenticateController>
        /*
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
        }*/
    }
}
