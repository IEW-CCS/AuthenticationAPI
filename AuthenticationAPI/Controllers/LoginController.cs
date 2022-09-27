﻿using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using AuthenticationAPI.DtoS;
using AuthenticationAPI.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

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
            var HandleAPREGREG = HttpTrxServices.Where(s => s.ServiceName == TransService.ARREGREQ.ToString()).FirstOrDefault();
            if (HandleAPREGREG != null)
            {
                string httpTrxMsg = JsonSerializer.Serialize(Msg);
                Logger.LogInformation("Handle Http Trx = " + httpTrxMsg);
                return HandleAPREGREG.HandlepHttpTrx(Msg);
            }
            else
            {
                string _replyProcessStep = ProcessStep.ARREGPLY.ToString();
                Logger.LogInformation("ERROR !! APREGREQ Not Register.");
                int RTCode = (int)HttpAuthErrorCode.ServiceNotRegister;
                HttpTrx HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
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
