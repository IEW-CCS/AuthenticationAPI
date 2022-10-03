using AuthenticationAPI.DtoS;
using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.DBContext;
using AuthenticationAPI.Authenticate;

namespace AuthenticationAPI.Service
{
   
    public class ARREGREQService : IHttpTrxService
    {
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private readonly IEnumerable<IAuthenticate> Authenticates;
        private ObjectManager ObjectManagerInstance = null;

        public ARREGREQService(ILogger<ARREGREQService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager, IEnumerable<IAuthenticate>  authenticates)
        {
            Logger = logger;
            Configuration = configuration;
            SecurityManager = securitymanager;
            Authenticates = authenticates;
            ObjectManagerInstance = (ObjectManager)objectmanager.GetInstance;
        }

        public string ServiceName
        {
            get
            {
                return TransService.ARREGREQ.ToString();
            }
        }

        public HttpTrx HandlepHttpTrx(HttpTrx Msg)
        {
            HttpTrx HttpReply = null;
            string replyProcessStep = ProcessStep.ARREGPLY.ToString();
            string username = Msg.username;
            string devicetype = Msg.devicetype;

            if (username == string.Empty)
            {
                int RTCode = (int)HttpAuthErrorCode.UserNotExist;
                HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                return HttpReply;
            }
            else if (Msg.procstep != ProcessStep.ARREGREQ.ToString())
            {
                int RTCode = (int)HttpAuthErrorCode.ProcStepNotMatch;
                HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                return HttpReply;
            }
            else
            {
                string DecrypStr = this.DecryptBaseDES(Msg.datacontent);
                if (DecrypStr == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.DecryptError;
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                    return HttpReply;
                }
                else
                {
                    if (!DeserializeObj.TryParseJson(DecrypStr, out ARREGREQ apregreq))
                    {
                        int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                        HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                        return HttpReply;
                    }
                    else
                    {
                        string returnMsg = string.Empty;
                        if (CheckAuthUserInfo(username, apregreq, out returnMsg) == false)
                        {
                            int RTCode = (int)HttpAuthErrorCode.CheckAuthInfoFail;
                            HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode, returnMsg);
                            return HttpReply;
                        }
                        else
                        {
                            if (Handle_AREGREQ(username, devicetype,  apregreq) == false)
                            {
                                int RTCode = (int)HttpAuthErrorCode.ServiceProgressError;
                                HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                                return HttpReply;
                            }
                            else
                            {
                                HttpReply = ReplyAPREGPLY(username, devicetype, apregreq);
                                return HttpReply;
                            } 
                        }
                    }
                }
            }
        }

        // ---- In First Time Reg User BaseDES ----
        private string DecryptBaseDES(string DataContent)
        {
            string DecryptStr = string.Empty;
            try
            {
                AuthBaseDES objDes = new AuthBaseDES();
                DecryptStr = objDes.DecryptDES(DataContent);
            }
            catch
            {
                DecryptStr = string.Empty;
            }
            return DecryptStr;
        }

        //----- Call AuthenticateService Check User Info ------
        private bool CheckAuthUserInfo (string username, ARREGREQ apregreq, out string RetMsg)
        {
            RetMsg = string.Empty;
            var UserPassword_Auth = Authenticates.Where( a => a.AuthenticateName == AuthenticateService.USERINFO.ToString() ).FirstOrDefault();
            try
            {
                if (UserPassword_Auth != null)
                {
                    UserInfo userinfo = new UserInfo(username, apregreq.PassWord);
                    return UserPassword_Auth.CheckAuth(userinfo, out RetMsg);
                }
                else
                {
                    Logger.LogError("USERINFO Service Not Register, so can be Handle.");
                    RetMsg = "Authenticate Service not Register.";
                    return false;
                }
            }
            catch( Exception ex)
            {
                Logger.LogError("USERINFO Process Exception, Msg = " + ex.Message) ;
                RetMsg = "Authenticate Service Exception.";
                return false; ;
            }
        }
        private bool Handle_AREGREQ(string username, string devicetype, ARREGREQ apreqreg)
        {
            /* Handle AREGREQ 主要功能都在於 Update RSA Key 
             * UUID 
             * Create Credential Infomation              */

            bool result = false;
            try
            {
                UpdateSecurityManager(username, devicetype, apreqreg.ClientRSAPublicKey);
                CreateCredentialInfo(username, apreqreg.APPGuid, apreqreg.APPVersion);
                InsertDeviceMacInfo(apreqreg.DeviceMacAddress);
                result = true;
            }
            catch (Exception ex)
            {
                result = false;
                Logger.LogError("Handle AREGREQ  Error, Msg = " + ex.Message);
            }
            return result;
        }

        private void UpdateSecurityManager (string username, string devicetype, string clientPublicKey)
        {
            try
            {
                SecurityManager.GetRSASecurity(username, devicetype).ClientID = username;
                SecurityManager.GetRSASecurity(username, devicetype).ClientPublicKey = clientPublicKey;
                SecurityManager.UpdateAuthSecurityToDB(username, devicetype);
            }
            catch(Exception ex)
            {
                throw new Exception("Update Security Manager Error, Msg = " + ex.Message );
            }
        }

        private HttpTrx ReplyAPREGPLY(string UserName, string DeviceType, ARREGREQ apregreq)
        {
            HttpTrx HttpReply = null;
            string replyProcessStep = ProcessStep.ARREGPLY.ToString();
            try
            {
                ARREGPLY ARRegReply = new ARREGPLY();
                ARRegReply.HttpToken = GenerateJWTTokenRegister(UserName);
                ARRegReply.ServerName = Configuration["Server:ServerName"];
                ARRegReply.HttpServiceURL = Configuration["Server:HttpRegisterServiceURL"];
                ARRegReply.WSServiceURL = Configuration["Server:WSServiceURL"];
                ARRegReply.ServerRSAPublicKey = SecurityManager.GetRSASecurity(UserName, DeviceType).PublicKey;
                string ARRegReplyJsonStr = JsonSerializer.Serialize(ARRegReply);

                AuthDES DES = new AuthDES();
                string DataContentDES = DES.EncryptDES(ARRegReplyJsonStr);

                ECS HESC = new ECS();
                HESC.Algo = "DES";
                HESC.Key = DES.GetKey();
                HESC.IV = DES.GetIV();

                string HESCJsonStr = JsonSerializer.Serialize(HESC);
                string ECSEncryptStr = SecurityManager.EncryptByClientPublicKey(UserName, DeviceType, HESCJsonStr, out string ECSEncryptRetMsg);

                if (ECSEncryptStr == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.ECSbyPublicKeyErrorRSA;
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                    HttpReply.returnmsg += ", Error Msg = " + ECSEncryptRetMsg;
                    return HttpReply;
                }
                else
                {
                    HttpReply = new HttpTrx();
                    HttpReply.username = UserName;
                    HttpReply.procstep = ProcessStep.ARREGPLY.ToString();
                    HttpReply.returncode = 0;
                    HttpReply.returnmsg = string.Empty;
                    HttpReply.datacontent = DataContentDES;
                    HttpReply.ecs = ECSEncryptStr;
                    HttpReply.ecssign = string.Empty;
                    return HttpReply;
                }
            }
            catch (Exception ex)
            {
                HttpReply = HttpReplyNG.Trx(replyProcessStep, ex);
                return HttpReply;
            }
        }

        // Generate Http Jwt Token ...
        private string GenerateJWTTokenRegister(string UserName)
        {
            var claims = new List<Claim>
            {
               new Claim(JwtRegisteredClaimNames.NameId,UserName)
            };

            claims.Add(new Claim(ClaimTypes.Role, "Register"));
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JWT:KEY"]));
            var jwt = new JwtSecurityToken
            (
                issuer: Configuration["JWT:Issuer"],
                audience: Configuration["JWT:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(10),
                signingCredentials: new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256)
            );
            var token = new JwtSecurityTokenHandler().WriteToken(jwt);
            return token.ToString();
        }

        private void CreateCredentialInfo(string name, string appGuid, string appVersion)
        {
            try
            {
                Credential_Info cred = new Credential_Info();
                cred.UserName = name;
                cred.APPGuid = appGuid;
                cred.APPVersion = appVersion;
                cred.DeviceUUID = string.Empty;
                cred.Nonce = 0;
                cred.CreateDateTime = DateTime.Now;
                ObjectManagerInstance.SetCredInfo(name, cred);
            }
            catch (Exception ex)
            {
                throw new Exception("Create Credential Info Exception, Msg = " + ex.Message);
            }
        }

        private void InsertDeviceMacInfo(string DeviceMacAddress)
        {
            try
            {
                ObjectManagerInstance.SetDeviceMACInfo(DeviceMacAddress);
            }
            catch (Exception ex)
            {
                throw new Exception("Insert Device Info Exception, Msg = " + ex.Message);
            }
        }
    }
}
