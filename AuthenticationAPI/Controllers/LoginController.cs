using AuthenticationAPI.DtoS;
using AuthenticationAPI.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthenticationAPI.Controllers
{
    
    [ApiController]
    [Route("api/[controller]")]
    [AllowAnonymous]
    public class LoginController : ControllerBase
    {
        private readonly ILogger<LoginController> Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        
        public LoginController(ILogger<LoginController> _logger, IConfiguration _configuration, ISecurityManager _securitymanager)
        {
            Logger = _logger;
            Configuration = _configuration;
            SecurityManager = _securitymanager;
        }

        [HttpPost("regLogin")]
        public HTTPTrx regLogin(HTTPTrx Msg)
        {
            HTTPTrx HttpReply = null;
            string UserName = Msg.UserName;
            string DeviceType = Msg.DeviceType;
            if (UserName == string.Empty)
            {
                int RTCode = (int)HttpAuthErrorCode.UserNotExist;
                HttpReply = this.ReplyNGHttpTrx(RTCode);
                return HttpReply;
            }
            else if(Msg.ProcStep  != ProcessStep.AREG_REQ.ToString())
            {
                int RTCode = (int)HttpAuthErrorCode.ProcStepNotMatch;
                HttpReply = this.ReplyNGHttpTrx(RTCode);
                return HttpReply;
            }
            else
            {
                //---- First Time Use BaseDES
                string DecrypStr = this.CheckBaseDESData(Msg.DataContent);
                if(DecrypStr == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.DecryptError;
                    HttpReply = this.ReplyNGHttpTrx(RTCode);
                    return HttpReply;
                }
                else
                {
                    APREGREQ apreqreg = DeserializeObj._APREGREQ(DecrypStr);
                    if(apreqreg == null)
                    {
                        int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                        HttpReply = this.ReplyNGHttpTrx(RTCode);
                        return HttpReply;
                    }
                    else
                    {
                        if(this.CheckAuth(apreqreg) != true)
                        {
                            int RTCode = (int)HttpAuthErrorCode.CheckAuthFailed;
                            HttpReply = this.ReplyNGHttpTrx(RTCode);
                            return HttpReply;
                        }
                        else
                        {
                            SecurityManager.GetRSASecurity(UserName, DeviceType).setClientID = UserName;
                            SecurityManager.GetRSASecurity(UserName, DeviceType).setClientPublicKey = apreqreg.ClientRSAPublicKey;
                            HttpReply = this.ReplyOKHttpTrx(UserName, DeviceType, apreqreg);
                            return HttpReply;
                        }
                    }
                }
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

        // Generate Http Jwt Token ...
        private string GenerateJWTToken(string UserName)
        {
            var claims = new List<Claim>
            {
               new Claim(JwtRegisteredClaimNames.NameId,UserName)
            };

            claims.Add(new Claim(ClaimTypes.Role, "Admin"));
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JWT:KEY"]));
            var jwt = new JwtSecurityToken
            (
                issuer: Configuration["JWT:Issuer"],
                audience: Configuration["JWT:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256)
            );
            var token = new JwtSecurityTokenHandler().WriteToken(jwt);
            return token.ToString();
        }
        private HTTPTrx ReplyOKHttpTrx(string userName,string DeviceType, APREGREQ apreqreg)
        {
            HTTPTrx HttpReply = null;
            APREGPLY ARRegReply = new APREGPLY();
            try
            {
              
                ARRegReply.Credential = GenerateCredential(userName);
                ARRegReply.HttpToken = GenerateJWTToken(userName); 
                ARRegReply.ServerName = Configuration["Server:ServerName"];
                ARRegReply.HttpServiceURL = Configuration["Server:HttpServiceName"];
                ARRegReply.WSServiceURL = Configuration["Server:WSServiceName"];
                ARRegReply.ServerRSAPublicKey = SecurityManager.GetRSASecurity(userName, DeviceType).PublicKey;
                ARRegReply.TimeStamp = DateTime.Now;
                string ARRegReplyJsonStr = JsonSerializer.Serialize(ARRegReply);

                AuthDES DES = new AuthDES();
                string DataContentDES = DES.EncryptDES(ARRegReplyJsonStr);

                HttpECS HESC = new HttpECS();
                HESC.Algo = "DES";
                HESC.Key = DES.GetKey();
                HESC.IV = DES.GetIV();

                string ECSEncryptRetMsg = string.Empty;
                string HESCJsonStr = JsonSerializer.Serialize(HESC);
                string ECSEncryptStr = SecurityManager.EncryptByClientPublicKey(userName, DeviceType, HESCJsonStr, out ECSEncryptRetMsg);

                if(ECSEncryptStr == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.ECSbyPublicKeyErrorRSA;
                    HttpReply = this.ReplyNGHttpTrx(RTCode);
                    HttpReply.ReturnMsg += ", Error Msg = " + ECSEncryptRetMsg;
                    return HttpReply;
                }

                else
                {
                    HttpReply = new HTTPTrx();
                    HttpReply.UserName = userName;
                    HttpReply.ProcStep = ProcessStep.AERG_PLY.ToString();
                    HttpReply.ReturnCode = 0;
                    HttpReply.ReturnMsg = string.Empty;
                    HttpReply.DataContent = DataContentDES;
                    HttpReply.ECS = ECSEncryptStr;
                    HttpReply.ECSSign = string.Empty;
                    return HttpReply;
                }
            }
            catch (Exception ex)
            {
                HttpReply = this.ReplyNGHttpTrx(ex);
                return HttpReply;
            }
        }

        private HTTPTrx ReplyNGHttpTrx( int retuenCode)
        {
            HTTPTrx HttpReply = new HTTPTrx();
            HttpReply.UserName = string.Empty;
            HttpReply.ProcStep = ProcessStep.AERG_PLY.ToString();
            HttpReply.ReturnCode = retuenCode;
            HttpReply.ReturnMsg = HttpAuthError.ErrorMsg(retuenCode);
            HttpReply.DataContent = string.Empty;
            return HttpReply;
        }

        private HTTPTrx ReplyNGHttpTrx(Exception ex)
        {
            HTTPTrx HttpReply = new HTTPTrx();
            HttpReply.UserName = string.Empty;
            HttpReply.ProcStep = ProcessStep.AERG_PLY.ToString();
            HttpReply.ReturnCode = 999;
            HttpReply.ReturnMsg = ex.Message;
            HttpReply.DataContent = string.Empty;
            return HttpReply;
        }

        private string CheckBaseDESData( string DataContent)
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

     

        // Wait for write logic
        private bool CheckAuth (APREGREQ apreqreg)
        {

            /* 認證比對目前只比對 User Name / Password in DB */
            /*
            Parallel.Invoke(() => result[0] = ProcessFuncAccountCheck(tmpVryopeData),
                                 () => result[1] = ProcessFuncMonitorSerialtCheck(tmpVryopeData));*/
            return true;
        }

        /*
        private bool ProcessFuncAccountCheck(clsVryope tmpVryopeData)
        {
            var AccountCheckService = _services.Where(s => s.ServiceName == "AccountCheckService").FirstOrDefault();
            if (AccountCheckService != null)
            {
                return AccountCheckService.vryope(tmpVryopeData);
            }
            else
            {
                return true;
            }
        }

        private bool ProcessFuncMonitorSerialtCheck(clsVryope tmpVryopeData)
        {
            var MonitorSerialCheckService = _services.Where(s => s.ServiceName == "MonitorSerialCheckService").FirstOrDefault();
            if (MonitorSerialCheckService != null)
            {
                return MonitorSerialCheckService.vryope(tmpVryopeData);
            }
            else
            {
                return false;
            }
        }*/

        private string GenerateCredential(string UserName)
        {
            /* 未來Credential String 產生規則為
             * BaseDES Credential Class obtain Content and Sign
             * Credential Content obtain 
             * String  Server
               String Type
               String  ClientPublicKey
               Datetime  CreateTime
               String   expire,
               Sign with signature RSA Private Key Sign in */
               

           
            return "Abcde12345";
        }
    }
}
