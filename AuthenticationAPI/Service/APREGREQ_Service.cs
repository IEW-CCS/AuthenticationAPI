using AuthenticationAPI.Controllers;
using AuthenticationAPI.DtoS;
using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Text.Json;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.DBContext;

namespace AuthenticationAPI.Service
{
   
    public class APREGREQ_Service : IHttpTrxService
    {
        private string _SeviceName = "APREGREQ";
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public APREGREQ_Service(ILogger<APREGREQ_Service> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
        {
            Logger = logger;
            Configuration = configuration;
            SecurityManager = securitymanager;
            ObjectManagerInstance = (ObjectManager)objectmanager.GetInstance;
        }

        public string ServiceName
        {
            get
            {
                return this._SeviceName;
            }
        }

        public HttpTrx HandlepHttpTrx(HttpTrx Msg)
        {
            HttpTrx HttpReply = null;
            string replyProcessStep = ProcessStep.AREG_PLY.ToString();
            string username = Msg.username;
            string devicetype = Msg.devicetype;

            if (username == string.Empty)
            {
                int RTCode = (int)HttpAuthErrorCode.UserNotExist;
                HttpReply = HttpReplyNG.Trx(replyProcessStep,RTCode);
                return HttpReply;
            }
            else if (Msg.procstep != ProcessStep.AREG_REQ.ToString())
            {
                int RTCode = (int)HttpAuthErrorCode.ProcStepNotMatch;
                HttpReply = HttpReplyNG.Trx(replyProcessStep,RTCode);
                return HttpReply;
            }
            else
            {
                //---- First Time Use BaseDES
                string DecrypStr = this.DecryptBaseDESData(Msg.datacontent);
                if (DecrypStr == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.DecryptError;
                    HttpReply = HttpReplyNG.Trx(replyProcessStep,RTCode);
                    return HttpReply;
                }
                else
                {
                    APREGREQ apregreq = DeserializeObj._APREGREQ(DecrypStr);
                    if (apregreq == null)
                    {
                        int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                        HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                        return HttpReply;
                    }
                    else
                    {
                        string returnMsg = string.Empty;
                        if (this.CheckAuth(username, apregreq, out returnMsg) != true)
                        {
                            int RTCode = (int)HttpAuthErrorCode.CheckAuthFailed;
                            HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode, returnMsg);
                            return HttpReply;
                        }
                        else
                        {
                            if (Handle_AREGREQ(username, devicetype,  apregreq) == false)
                            {
                                int RTCode = (int)HttpAuthErrorCode.ServerProgressError;
                                HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                                return HttpReply;
                            }
                            else
                            {
                                HttpReply = this.ReplyAPREGPLY(username, devicetype, apregreq);
                                return HttpReply;
                            } 
                        }
                    }
                }
            }
        }

        private bool Handle_AREGREQ(string username, string devicetype, APREGREQ apreqreg)
        {
            bool result = false;
            try
            {
                SecurityManager.GetRSASecurity(username, devicetype).ClientID = username;
                SecurityManager.GetRSASecurity(username, devicetype).ClientPublicKey = apreqreg.ClientRSAPublicKey;
                SecurityManager.UpdateAuthSecurityToDB(username, devicetype);
                UpdateCredInfo(username, apreqreg.APPGuid, apreqreg.APPVersion);
                UpdateDeviceInfo(apreqreg.DeviceMacAddress);
                result = true;
            }
            catch (Exception ex)
            {
                result = false;
                Logger.LogError("Handle DUUID Report Error, Msg = " + ex.Message);
            }
            return result;
        }

        private HttpTrx ReplyAPREGPLY(string UserName, string DeviceType, APREGREQ apregreq)
        {
            HttpTrx HttpReply = null;
            string replyProcessStep = ProcessStep.AREG_PLY.ToString();
           
            try
            {
                APREGPLY ARRegReply = new APREGPLY();
                ARRegReply.HttpToken = GenerateJWTToken(UserName);
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

                string ECSEncryptRetMsg = string.Empty;
                string HESCJsonStr = JsonSerializer.Serialize(HESC);
                string ECSEncryptStr = SecurityManager.EncryptByClientPublicKey(UserName, DeviceType, HESCJsonStr, out ECSEncryptRetMsg);

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
                    HttpReply.procstep = ProcessStep.AREG_PLY.ToString();
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

      

        private string DecryptBaseDESData(string DataContent)
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

        // Generate Http Jwt Token ...
        private string GenerateJWTToken(string UserName)
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

        private bool CheckAuth(string username, APREGREQ apregreq, out string RetMsg)
        {
            RetMsg = string.Empty;
            return true;
            /*
             *   最後Call 這個 Interface 對應 
             *   UserAuthenticate
            */
        }

        private void UpdateCredInfo(string name, string appGuid, string appVersion)
        {
            var cred = ObjectManagerInstance.GetCredInfo(name);
            cred.UserName = name;
            cred.APPGuid = appGuid;
            cred.APPVersion = appVersion;
            ObjectManagerInstance.SetCredInfo(name, cred);
        }

        private void UpdateDeviceInfo( string deviceNo)
        {
            string provider = Configuration["ConnectionStrings:Provider"];
            string connectstring = Configuration["ConnectionStrings:DefaultConnection"];
            try
            {
                using (var db = new DBContext.MetaDBContext(provider, connectstring))
                {
                    AUTH_DEVICE DeviceInfo = new AUTH_DEVICE();
                    DeviceInfo.device = deviceNo;
                    db.auth_device.Add(DeviceInfo);
                    db.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                Logger.LogWarning("Device Info Upload Exception, Msg = " + ex.Message);
            }
        }
    }
}
