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
            string _replyProcessStep = ProcessStep.AREG_PLY.ToString();
            string _username = Msg.UserName;
            string _devicetype = Msg.DeviceType;

            if (_username == string.Empty)
            {
                int RTCode = (int)HttpAuthErrorCode.UserNotExist;
                HttpReply = HttpReplyNG.Trx(_replyProcessStep,RTCode);
                return HttpReply;
            }
            else if (Msg.ProcStep != ProcessStep.AREG_REQ.ToString())
            {
                int RTCode = (int)HttpAuthErrorCode.ProcStepNotMatch;
                HttpReply = HttpReplyNG.Trx(_replyProcessStep,RTCode);
                return HttpReply;
            }
            else
            {
                //---- First Time Use BaseDES
                string DecrypStr = this.DecryptBaseDESData(Msg.DataContent);
                if (DecrypStr == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.DecryptError;
                    HttpReply = HttpReplyNG.Trx(_replyProcessStep,RTCode);
                    return HttpReply;
                }
                else
                {
                    APREGREQ apregreq = DeserializeObj._APREGREQ(DecrypStr);
                    if (apregreq == null)
                    {
                        int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                        HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                        return HttpReply;
                    }
                    else
                    {
                        string returnMsg = string.Empty;
                        if (this.CheckAuth(apregreq, out returnMsg) != true)
                        {
                            int RTCode = (int)HttpAuthErrorCode.CheckAuthFailed;
                            HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode, returnMsg);
                            return HttpReply;
                        }
                        else
                        {
                            if (Handle_AREGREQ(_username, _devicetype,  apregreq) == false)
                            {
                                int RTCode = (int)HttpAuthErrorCode.ServerProgressError;
                                HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                                return HttpReply;
                            }
                            else
                            {
                                HttpReply = this.ReplyAPREGPLY(_username, _devicetype, apregreq);
                                return HttpReply;
                            } 
                        }
                    }
                }
            }
        }

        private HttpTrx ReplyAPREGPLY(string userName, string DeviceType, APREGREQ apregreq)
        {
            HttpTrx HttpReply = null;
            string _replyProcessStep = ProcessStep.AREG_PLY.ToString();
            APREGPLY ARRegReply = new APREGPLY();
            try
            {

                ARRegReply.HttpToken = GenerateJWTToken(userName);
                ARRegReply.ServerName = Configuration["Server:ServerName"];
                ARRegReply.HttpServiceURL = Configuration["Server:HttpServiceName"];
                ARRegReply.WSServiceURL = Configuration["Server:WSServiceName"];
                ARRegReply.ServerRSAPublicKey = SecurityManager.GetRSASecurity(userName, DeviceType).PublicKey;
                ARRegReply.TimeStamp = DateTime.Now;
                string ARRegReplyJsonStr = JsonSerializer.Serialize(ARRegReply);

                AuthDES DES = new AuthDES();
                string DataContentDES = DES.EncryptDES(ARRegReplyJsonStr);

                ECS HESC = new ECS();
                HESC.Algo = "DES";
                HESC.Key = DES.GetKey();
                HESC.IV = DES.GetIV();

                string ECSEncryptRetMsg = string.Empty;
                string HESCJsonStr = JsonSerializer.Serialize(HESC);
                string ECSEncryptStr = SecurityManager.EncryptByClientPublicKey(userName, DeviceType, HESCJsonStr, out ECSEncryptRetMsg);

                if (ECSEncryptStr == string.Empty)
                {
                    int RTCode = (int)HttpAuthErrorCode.ECSbyPublicKeyErrorRSA;
                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                    HttpReply.ReturnMsg += ", Error Msg = " + ECSEncryptRetMsg;
                    return HttpReply;
                }

                else
                {
                    HttpReply = new HttpTrx();
                    HttpReply.UserName = userName;
                    HttpReply.ProcStep = ProcessStep.AREG_PLY.ToString();
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
                HttpReply = HttpReplyNG.Trx(_replyProcessStep, ex);
                return HttpReply;
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
                result = true;
            }
            catch (Exception ex)
            {
                result = false;
                Logger.LogError("Handle DUUID Report Error, Msg = " + ex.Message);
            }
            return result;
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

        private bool CheckAuth(APREGREQ apregreq, out string RetMsg)
        {
            string provider = Configuration["ConnectionStrings:Provider"];
            string connectstring = Configuration["ConnectionStrings:DefaultConnection"];
            string userName = apregreq.UserName;
            string passWord = apregreq.PassWord;
            RetMsg = string.Empty;
            AuthBaseDES objDes = new AuthBaseDES();
            string securityPssword = string.Empty;
            if (IsNumandEG(userName) == true && IsNumandEG(passWord) == true)
            {
                using (var db = new DBContext.MetaDBContext(provider, connectstring))
                {
                    securityPssword = objDes.EncryptDES(passWord);
                    var user = db.auth_info.AsQueryable().Where(o => o.username == userName && o.password == securityPssword).FirstOrDefault();
                    if (user != null)
                    {
                        return true;
                    }
                    else
                    {
                        RetMsg = "UserName and Password Not Match.";
                        return false;
                    }
                }
            }
            else
            {
                RetMsg = "UserName and Password obtain illegal characters.";
                return false;
            }
        }

        private void UpdateCredInfo(string name, string appGuid, string appVersion)
        {

            var cred = ObjectManagerInstance.GetCredInfo(name);
            cred.ServerName = Configuration["Server:ServerName"];
            cred.UserName = name;
            cred.APPGuid = appGuid;
            cred.APPVersion = appVersion;
            cred.CreateDateTime = DateTime.Now;
            ObjectManagerInstance.SetCredInfo(name, cred);

        }
        private bool IsNumandEG(string word)
        {
            Regex NumandEG = new Regex("[^A-Za-z0-9_.]");
            return !NumandEG.IsMatch(word);
        }
    }
}
