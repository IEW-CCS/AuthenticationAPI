﻿using AuthenticationAPI.DtoS;
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
    [Authorize(Roles = "Admin, Administrator, Verify")]

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

                        case ProcessStep.VCON_REQ:
                            {
                                var HandleAPVRYREQ = HttpTrxServices.Where(s => s.ServiceName == "AVCONREQ").FirstOrDefault();
                                if (HandleAPVRYREQ != null)
                                {
                                    ObjectManagerInstance.SetVerifyStatus(UserName, ProcStep);
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation("Handle Http Trx = " + httpTrxMsg);
                                    HttpReply = HandleAPVRYREQ.HandlepHttpTrx(Msg);
                                    if (HttpReply.returncode == 0)
                                    {
                                        ObjectManagerInstance.SetVerifyStatus(UserName, HttpReply.procstep);
                                    }
                                }
                                else
                                {
                                    string _replyProcessStep = ProcessStep.VCON_PLY.ToString();
                                    Logger.LogInformation("ERROR !! AVCONREQ Not Register.");
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
                                    ObjectManagerInstance.SetVerifyStatus(UserName, ProcStep);
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation("Handle Http Trx = " + httpTrxMsg);
                                    HttpReply = HandleAPVRYREQ.HandlepHttpTrx(Msg);
                                    if (HttpReply.returncode == 0)
                                    {
                                        ObjectManagerInstance.SetVerifyStatus(UserName, HttpReply.procstep);
                                        string hashPassword = ObjectManagerInstance.GetHashPassword(UserName);
                                        if (hashPassword != string.Empty)
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

                     
                        case ProcessStep.AHPW_REQ:
                            {
                                var HandleAPHPWREQ = HttpTrxServices.Where(s => s.ServiceName == "APHPWREQ").FirstOrDefault();
                                if (HandleAPHPWREQ != null)
                                {
                                    string httpTrxMsg = JsonSerializer.Serialize(Msg);
                                    Logger.LogInformation("Handle Http Trx = " + httpTrxMsg);
                                    HttpReply = HandleAPHPWREQ.HandlepHttpTrx(Msg);
                                }
                                else
                                {
                                    string _replyProcessStep = ProcessStep.AHPW_PLY.ToString();
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

        private bool CheckProcStep(string procStep)
        {
            bool result = false;
            try
            {
                ProcessStep PStep = (ProcessStep)Enum.Parse(typeof(ProcessStep), procStep);
                switch (PStep)
                {
                    case ProcessStep.VCON_REQ:
                    case ProcessStep.AVRY_REQ:
                    case ProcessStep.AHPW_REQ:
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

        private void LDAPPWChange(string UserName, string hashPassword)
        {
            //  Call LDAP Change Password Function

        }


    }
}