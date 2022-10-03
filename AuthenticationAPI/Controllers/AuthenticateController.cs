using AuthenticationAPI.DtoS;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthenticationAPI.Controllers
{

    [ApiController]
    [Route("api/[controller]")]
    [EnableCors("CorsPolicy")]
    [Authorize(Roles = "Admin, Administrator, Authenticate")]
    public class AuthenticateController : ControllerBase
    {
        private readonly ILogger Logger;
        private readonly IEnumerable<IHttpTrxService> HttpTrxServices;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private readonly IQueueManager QueueManager;
        // private readonly ILDAPManagement OpenVPN_LDAP;
        private readonly ObjectManager ObjectManagerInstance;

        public AuthenticateController(ILogger<AuthenticateController> logger, IEnumerable<IHttpTrxService> services, IQueueManager queuemanager, IObjectManager objectmanager, IConfiguration configuration, ISecurityManager securitymanager)
        {
            Logger = logger;
            HttpTrxServices = services;
            Configuration = configuration;
            SecurityManager = securitymanager;
            QueueManager = queuemanager;
            // OpenVPN_LDAP = openvpnldap;
            ObjectManagerInstance = (ObjectManager)objectmanager.GetInstance;
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
                        case ProcessStep.AACONREQ:
                            {
                                var HandleAPVRYREQ = HttpTrxServices.Where(s => s.ServiceName == TransService.AACONREQ.ToString()).FirstOrDefault();
                                if (HandleAPVRYREQ != null)
                                {
                                    ObjectManagerInstance.SetVerifyStatus(UserName, ProcStep);
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation(String.Format("[Authenticate] Service Request, User ={0}, DeviceType = {1}, ProcessStep = {2}, RawData = {3}.", Msg.username, Msg.devicetype, Msg.procstep, httpTrxMsg));
                                    HttpReply = HandleAPVRYREQ.HandlepHttpTrx(Msg);
                                    if (HttpReply.returncode == 0)
                                    {
                                        ObjectManagerInstance.SetVerifyStatus(UserName, HttpReply.procstep);
                                    }
                                }
                                else
                                {
                                    Logger.LogError("AACONREQ Service Not Register, so can be Handle.");
                                    string ReplyProcessStep = ProcessStep.AACONPLY.ToString();
                                    int RTCode = (int)HttpAuthErrorCode.ServiceNotRegister;
                                    HttpReply = HttpReplyNG.Trx(ReplyProcessStep, RTCode);
                                }
                                break;
                            }
                        case ProcessStep.AAUTHREQ:
                            {
                                var HandleAPVRYREQ = HttpTrxServices.Where(s => s.ServiceName == TransService.AAUTHREQ.ToString()).FirstOrDefault();
                                if (HandleAPVRYREQ != null)
                                {
                                    ObjectManagerInstance.SetVerifyStatus(UserName, ProcStep);
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation(String.Format("[Authenticate] Service Request, User ={0}, DeviceType = {1}, ProcessStep = {2}, RawData = {3}.", Msg.username, Msg.devicetype, Msg.procstep, httpTrxMsg));
                                    HttpReply = HandleAPVRYREQ.HandlepHttpTrx(Msg);
                                    if (HttpReply.returncode == 0)
                                    {
                                        ObjectManagerInstance.SetVerifyStatus(UserName, HttpReply.procstep);
                                    }
                                }
                                else
                                {
                                    Logger.LogError("AAUTHREQ Service Not Register, so can be Handle.");
                                    string ReplyProcessStep = ProcessStep.AAUTHPLY.ToString();
                                    int RTCode = (int)HttpAuthErrorCode.ServiceNotRegister;
                                    HttpReply = HttpReplyNG.Trx(ReplyProcessStep, RTCode);
                                }
                                break;
                            }  
                        case ProcessStep.AAPSWREQ:
                            {
                                var HandleAPHPWREQ = HttpTrxServices.Where(s => s.ServiceName == TransService.AAPSWREQ.ToString()).FirstOrDefault();
                                if (HandleAPHPWREQ != null)
                                {
                                    ObjectManagerInstance.SetVerifyStatus(UserName, ProcStep);
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation(String.Format("[Authenticate] Service Request, User ={0}, DeviceType = {1}, ProcessStep = {2}, RawData = {3}.", Msg.username, Msg.devicetype, Msg.procstep, httpTrxMsg));
                                    HttpReply = HandleAPHPWREQ.HandlepHttpTrx(Msg);
                                    if (HttpReply.returncode == 0)
                                    {
                                        string hashPassword = ObjectManagerInstance.GetHashPassword(UserName);
                                        if (hashPassword != string.Empty)
                                        {
                                            if(OpenVPNPassWordChange(UserName, hashPassword, out string ReturnMsg) == false)
                                            {
                                                Logger.LogError(string.Format("OpenVPN Change Password Error, Msg = {0}.", ReturnMsg));
                                                string ReplyProcessStep = ProcessStep.AAPSWPLY.ToString();
                                                int RTCode = (int)HttpAuthErrorCode.ChangeHashPasswordError;
                                                HttpReply = HttpReplyNG.Trx(ReplyProcessStep, RTCode);
                                            }
                                            else
                                            {
                                                ObjectManagerInstance.SetVerifyStatus(UserName, HttpReply.procstep);
                                            }
                                        }
                                        else
                                        {
                                            Logger.LogError("Hash PassWord Generate Error.");
                                            string ReplyProcessStep = ProcessStep.AAPSWPLY.ToString();
                                            int RTCode = (int)HttpAuthErrorCode.HashPasswordCreateError;
                                            HttpReply = HttpReplyNG.Trx(ReplyProcessStep, RTCode);
                                        }
                                    }
                                }
                                else
                                {
                                    Logger.LogError("AAPSWREQ Service Not Register, so can be Handle.");
                                    string ReplyProcessStep = ProcessStep.AAPSWPLY.ToString();
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
                    case ProcessStep.AACONREQ:
                    case ProcessStep.AAUTHREQ:
                    case ProcessStep.AAPSWREQ:
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

        private bool OpenVPNPassWordChange(string userName, string hashPassword,  out string resultMessage)
        {
            bool result = false;
            resultMessage = string.Empty;

            try
            {
                result = true;
                //result = OpenVPN_LDAP.ModifyUserPassword(UserName, hashPassword);
            }
            catch (Exception ex)
            {
                result = false;
                Logger.LogError("OpenVPN Change Password Error, Msg = " + ex.Message);

            }
            return result;
        }
    }
}
