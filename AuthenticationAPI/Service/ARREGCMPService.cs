using AuthenticationAPI.DtoS;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace AuthenticationAPI.Service
{
    public class ARREGCMPService : IHttpTrxService
    {
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;

        public ARREGCMPService(ILogger<ARREGCMPService> logger, IConfiguration configuration, ISecurityManager securitymanager)
        {
            //MetaDBContext dbcontext
            Logger = logger;
            Configuration = configuration;
            SecurityManager = securitymanager;
        }

        public string ServiceName
        {
            get
            {
                return TransService.ARREGCMP.ToString();
            }
        }

        public HttpTrx HandlepHttpTrx(HttpTrx Msg)
        {
            HttpTrx HttpReply = null;
            string replyProcessStep = ProcessStep.ARREGFIN.ToString();
            string userName = Msg.username;
            string deviceType = Msg.devicetype;

            if (userName == string.Empty)
            {
                int RTCode = (int)HttpAuthErrorCode.UserNotExist;
                HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                return HttpReply;
            }
            else
            {
                int ReturnCode = SecurityManager.GetRSASecurity(userName, deviceType).Decrypt_Check(Msg.ecs, Msg.ecssign, out string DecryptECS, out string ReturnMsg);
                if (ReturnCode != 0)
                {
                    HttpReply = HttpReplyNG.Trx(replyProcessStep, ReturnCode, ReturnMsg);
                    return HttpReply;
                }
                else
                {
                    if (!DeserializeObj.TryParseJson(DecryptECS, out ECS HESC))
                    {
                        int RTCode = (int)HttpAuthErrorCode.DecryptECSError;
                        HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                        return HttpReply;
                    }
                    else
                    {
                        string DecrypContent = DecryptDESData(HESC.Key, HESC.IV, Msg.datacontent);
                        if (DecrypContent == string.Empty)
                        {
                            int RTCode = (int)HttpAuthErrorCode.DecryptError;
                            HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                            return HttpReply;
                        }
                        else
                        {
                            if (!DeserializeObj.TryParseJson(DecrypContent, out ARREGCMP arregcmp))
                            {
                                int RTCode = (int)HttpAuthErrorCode.DeserializeError;
                                HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                                return HttpReply;
                            }
                            else
                            {
                                if (Handle_APREGCMP(userName, deviceType, arregcmp) == false)
                                {
                                    int RTCode = (int)HttpAuthErrorCode.ServiceProgressError;
                                    HttpReply = HttpReplyNG.Trx(replyProcessStep, RTCode);
                                    return HttpReply;
                                }
                                else
                                {
                                    HttpReply = ReplyARREGFIN(userName, deviceType, arregcmp);
                                    return HttpReply;
                                }
                            }
                        }
                    }
                }
            }
        }

        private bool Handle_APREGCMP(string username, string devicetype, ARREGCMP arregcmp)
        {
            //---暫時根據 ARREGCMP的結果回覆
            bool result = arregcmp.Result == "OK" ? true : false;
            return result;
        }

        private HttpTrx ReplyARREGFIN(string username, string devicetype, ARREGCMP arregcmp)
        {
            HttpTrx HttpReply = new HttpTrx();
            ARREGFIN APRegFinish = null;
            string replyProcessStep = ProcessStep.ARREGFIN.ToString();
            try
            {
                APRegFinish = new ARREGFIN();
                APRegFinish.AuthenticationToken = GenerateAuthenticationJWTToken(username);
                APRegFinish.AuthenticationURL = Configuration["Server:HttpAuthServiceURL"];
                Logger.LogInformation("Reply ARREGFIN Result, User = {0}, DeviceType = {1}, AuthURL ={2}, AuthToken = {3}.", username, devicetype, APRegFinish.AuthenticationURL, APRegFinish.AuthenticationToken);

                string ARRegFinishJsonStr = JsonSerializer.Serialize(APRegFinish);

                AuthDES DES = new AuthDES();
                string DataContentDES = DES.EncryptDES(ARRegFinishJsonStr);

                ECS HESC = new ECS();
                HESC.Algo = "DES";
                HESC.Key = DES.GetKey();
                HESC.IV = DES.GetIV();

                string HESCJsonStr = JsonSerializer.Serialize(HESC);
                string ECSEncryptStr = SecurityManager.Encrypt_Sign(username, devicetype, HESCJsonStr, out string SignStr, out string ECSEncryptRetMsg);

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
                    HttpReply.username = username;
                    HttpReply.procstep = replyProcessStep;
                    HttpReply.returncode = 0;
                    HttpReply.returnmsg = string.Empty;
                    HttpReply.datacontent = DataContentDES;
                    HttpReply.ecs = ECSEncryptStr;
                    HttpReply.ecssign = SignStr;
                    return HttpReply;
                }
            }
            catch (Exception ex)
            {
                HttpReply = HttpReplyNG.Trx(replyProcessStep, ex);
            }
            return HttpReply;
        }

        private string DecryptDESData(string key, string iv, string DataContent)
        {
            AuthDES objDes = new AuthDES(key, iv);
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
        private string GenerateAuthenticationJWTToken(string UserName)
        {
            var claims = new List<Claim>
            {
               new Claim(JwtRegisteredClaimNames.NameId,UserName)
            };

            claims.Add(new Claim(ClaimTypes.Role, "Authenticate"));
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["JWT:KEY"]));
            var jwt = new JwtSecurityToken
            (
                issuer: Configuration["JWT:Issuer"],
                audience: Configuration["JWT:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMonths(6),
                signingCredentials: new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256)
            );
            var token = new JwtSecurityTokenHandler().WriteToken(jwt);
            return token.ToString();
        }
    }
}
