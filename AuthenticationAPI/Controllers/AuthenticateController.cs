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

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace AuthenticationAPI.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    [EnableCors("CorsPolicy")]
    public class AuthenticateController : ControllerBase
    {
        private readonly ILogger Logger;
        private readonly IEnumerable<IHttpTrxService> HttpTrxServices;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private readonly IQueueManager QueueManager;
        private readonly ObjectManager ObjectManagerInstance;

        public AuthenticateController(ILogger<AuthenticateController> logger, IEnumerable<IHttpTrxService> services, IQueueManager queuemanager, IObjectManager objectmanager, IConfiguration configuration, ISecurityManager securitymanager)
        {
            Logger = logger;
            HttpTrxServices = services;
            Configuration = configuration;
            SecurityManager = securitymanager;
            QueueManager = queuemanager;
            ObjectManagerInstance = (ObjectManager) objectmanager.GetInstance;
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

        // POST api/<AuthenticateController>
        [HttpPost]
        [EnableCors("CorsPolicy")]
        public HttpTrx Post([FromBody] HttpTrx Msg)
        {

            HttpTrx HttpReply = null;
            string UserName = Msg.UserName;
            string DeviceType = Msg.DeviceType;
            string ProcStep = Msg.ProcStep;

            if (CheckProcStep(ProcStep) == false)
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
                        case ProcessStep.UUID_RPT:
                            {
                                var HandleDUUIDRPT = HttpTrxServices.Where(s => s.ServiceName == "DUUIDRPT").FirstOrDefault();
                                if (HandleDUUIDRPT != null)
                                {
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation("Handle Http Trx = " + httpTrxMsg);
                                    HttpReply = HandleDUUIDRPT.HandlepHttpTrx(Msg);
                                }
                                else
                                {
                                    string _replyProcessStep = ProcessStep.UUID_ACK.ToString();
                                    Logger.LogInformation("ERROR !! DUUIDRPT Not Register.");
                                    int RTCode = (int)HttpAuthErrorCode.ServiceNotRegister;
                                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                                }
                                break;
                            }

                        case ProcessStep.CRED_REQ:
                            {
                                var HandleCREDREQ = HttpTrxServices.Where(s => s.ServiceName == "CCREDREQ").FirstOrDefault();
                                if (HandleCREDREQ != null)
                                {
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation("Handle Http Trx = " + httpTrxMsg);
                                    HttpReply = HandleCREDREQ.HandlepHttpTrx(Msg);
                                    if(HttpReply.ReturnCode == 0)
                                    {
                                        string Credential = ObjectManagerInstance.GetCredential(UserName);
                                        string DeviceUUID = ObjectManagerInstance.GetDeviceUUID(UserName);

                                        if (Credential != string.Empty && DeviceUUID != string.Empty)
                                        {
                                            UUIDANN(UserName, Credential, DeviceUUID);
                                        }
                                        else
                                        {
                                            Logger.LogError("Credential = " + Credential + "DeviceUUID = " + DeviceUUID + ", With Empty, So Skip Handle.");
                                        }
                                    }
                                }
                                else
                                {
                                    string _replyProcessStep = ProcessStep.CRED_PLY.ToString();
                                    Logger.LogInformation("ERROR !! DUUIDRPT Not Register.");
                                    int RTCode = (int)HttpAuthErrorCode.ServiceNotRegister;
                                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                                }
                                break;
                            }

                        case ProcessStep.AVRY_REQ:
                            {
                                var HandleAPVRYREQ = HttpTrxServices.Where(s => s.ServiceName == "APVRYREQ").FirstOrDefault();
                                if (HandleAPVRYREQ != null)
                                {
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation("Handle Http Trx = " + httpTrxMsg);
                                    HttpReply = HandleAPVRYREQ.HandlepHttpTrx(Msg);
                                    if (HttpReply.ReturnCode == 0)
                                    {
                                        string hashPassword = ObjectManagerInstance.GetHashPassword(UserName);
                                        if(hashPassword != string.Empty)
                                        {
                                            LDAPPWChange(UserName, hashPassword);
                                        }
                                      
                                    }
                                }
                                else
                                {
                                    string _replyProcessStep = ProcessStep.AVRY_PLY.ToString();
                                    Logger.LogInformation("ERROR !! DUUIDRPT Not Register.");
                                    int RTCode = (int)HttpAuthErrorCode.ServiceNotRegister;
                                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                                }
                                break;
                            }

                        case ProcessStep.AREG_CMP:
                            {
                                var HandleAREGCMP = HttpTrxServices.Where(s => s.ServiceName == "APREGCMP").FirstOrDefault();
                                if (HandleAREGCMP != null)
                                {
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation("Handle Http Trx = " + httpTrxMsg);
                                    HttpReply = HandleAREGCMP.HandlepHttpTrx(Msg);
                                }
                                else
                                {
                                    string _replyProcessStep = ProcessStep.AREG_FIN.ToString();
                                    Logger.LogInformation("ERROR !! APREGCMP Not Register.");
                                    int RTCode = (int)HttpAuthErrorCode.ServiceNotRegister;
                                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                                }
                                break;
                            }

                        case ProcessStep.AVRY_CMP:
                            {
                                var HandleAVRYCMP = HttpTrxServices.Where(s => s.ServiceName == "APVRYCMP").FirstOrDefault();
                                if (HandleAVRYCMP != null)
                                {
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation("Handle Http Trx = " + httpTrxMsg);
                                    HttpReply = HandleAVRYCMP.HandlepHttpTrx(Msg);
                                }
                                else
                                {
                                    string _replyProcessStep = ProcessStep.AVRY_FIN.ToString();
                                    Logger.LogInformation("ERROR !! APREGCMP Not Register.");
                                    int RTCode = (int)HttpAuthErrorCode.ServiceNotRegister;
                                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
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

        private bool CheckProcStep(string procStep)
        {
            bool result = false;
            try
            {
                ProcessStep PStep = (ProcessStep)Enum.Parse(typeof(ProcessStep), procStep);
                switch (PStep)
                {
                    case ProcessStep.UUID_RPT:
                    case ProcessStep.CRED_REQ:  
                    case ProcessStep.AREG_CMP:
                    case ProcessStep.AVRY_REQ: 
                    case ProcessStep.AVRY_CMP:
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


        private void UUIDANN(string username, string credentialcontent, string DeviceUUID)
        {
            WSTrx WebSocketReply = null;
            string ReplyProcStep = ProcessStep.UUID_ANN.ToString();
            string Device_type = DeviceType.CONSOLE.ToString();
            DUUIDANN uuidann = new DUUIDANN();
            try
            {
                uuidann.ServerName = Configuration["Server:ServerName"];
                uuidann.DeviceUUID = DeviceUUID;
                uuidann.Credential = credentialcontent;
                uuidann.TimeStamp = DateTime.Now;

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
                string ECSEncryptStr = SecurityManager.Encrypt_Sign(username, Device_type, HESCJsonStr, out SignStr, out ECSEncryptRetMsg);

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
                    SendWebsocket(username, string.Empty, WSReplyJsonStr);
                }
            }
            catch (Exception ex)
            {
                Logger.LogError("UID ANN Error, Err Msg = " + ex.Message);
            }
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
                Logger.LogError("Send Data via WebSocket Error, Err Msg = " + Ex.Message);
            }
        }

        private void LDAPPWChange(string UserName, string hashPassword)
        {


        }
    }
}
