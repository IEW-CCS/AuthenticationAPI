using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using AuthenticationAPI.DtoS;
using AuthenticationAPI.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AuthenticationAPI.Controllers
{
    
    [ApiController]
    [Route("api/[controller]")]
    [AllowAnonymous]
    public class LoginController : ControllerBase
    {
        private readonly ILogger Logger;
        private readonly IEnumerable<IHttpTrxService> HttpTrxServices;
        public LoginController(ILogger<LoginController> logger, IEnumerable<IHttpTrxService> httptrxServices)
        {
            Logger = logger;
            HttpTrxServices = httptrxServices;
        }

        [HttpPost("regLogin")]
        public HttpTrx regLogin(HttpTrx Msg)
        {
            // 抽出 ARREGREQ Service
            var HandleAPREGREG = HttpTrxServices.Where(s => s.ServiceName == TransService.ARREGREQ.ToString()).FirstOrDefault();
            if (HandleAPREGREG != null)
            {
                string httpTrxMsg = JsonSerializer.Serialize(Msg);
                Logger.LogInformation(String.Format("[Login] Service Request, User ={0}, DeviceType = {1}, ProcessStep = {2}, RawData = {3}.",Msg.username,Msg.devicetype, Msg.procstep, httpTrxMsg));
                return HandleAPREGREG.HandlepHttpTrx(Msg);
            }
            else
            {
                Logger.LogError("APREGREQ Service Not Register, so can be Handle.");
                string ReplyProcessStep = ProcessStep.ARREGPLY.ToString();
                int RTCode = (int)HttpAuthErrorCode.ServiceNotRegister;
                HttpTrx HttpReply = HttpReplyNG.Trx(ReplyProcessStep, RTCode);
                return HttpReply;
            }
        }

        [HttpGet("NoLogin")]
        public string noLogin()
        {
            return "未登入";
        }

        [HttpGet("NoAccess")]
        public string noAccess()
        {
            return "沒有權限";
        } 
    }
}
