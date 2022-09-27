﻿using AuthenticationAPI.DtoS;
using AuthenticationAPI.Kernel;
using AuthenticationAPI.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace AuthenticationAPI.Service
{
    public class CRCRLREQServiceLite : IHttpTrxService
    {
        private string _SeviceName = TransServiceLite.CRCRLREQ_Lite.ToString();
        private readonly ILogger Logger;
        private readonly IConfiguration Configuration;
        private readonly ISecurityManager SecurityManager;
        private ObjectManager ObjectManagerInstance = null;

        public CRCRLREQServiceLite(ILogger<CRCRLREQService> logger, IConfiguration configuration, ISecurityManager securitymanager, IObjectManager objectmanager)
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

            string _replyProcessStep = ProcessStep.CRCRLPLY.ToString();
            string _userName = Msg.username;
            string _deviceType = Msg.devicetype;

            if (_userName == string.Empty)
            {
                int RTCode = (int)HttpAuthErrorCode.UserNotExist;
                HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                return HttpReply;
            }
            else
            {
                if (Handle_CCREDREQ(_userName, _deviceType) == false)
                {
                    int RTCode = (int)HttpAuthErrorCode.ServerProgressError;
                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                    return HttpReply;
                }
                else
                {
                    GenerateCredential(_userName);
                    HttpReply = this.ReplyCCREQPLY(_userName, _deviceType);
                    return HttpReply;
                }
            }
        }


        private HttpTrx ReplyCCREQPLY(string username, string devicetype)
        {
            HttpTrx HttpReply = new HttpTrx();
            CRCRLPLY CCredReply = new CRCRLPLY();
            string _replyProcessStep = ProcessStep.CRCRLPLY.ToString();

            try
            {

                Credential card = this.ObjectManagerInstance.GetCredential(username);
                if (card == null)
                {
                    int RTCode = (int)HttpAuthErrorCode.CreateCredentialError;
                    HttpReply = HttpReplyNG.Trx(_replyProcessStep, RTCode);
                    return HttpReply;
                }

                CCredReply.CredentialSign = card.CredSign.Substring(0,8);

                string CCredReplyJsonStr = System.Text.Json.JsonSerializer.Serialize(CCredReply);
                HttpReply = new HttpTrx();
                HttpReply.username = username;
                HttpReply.procstep = _replyProcessStep;
                HttpReply.returncode = 0;
                HttpReply.returnmsg = string.Empty;
                HttpReply.datacontent = CCredReplyJsonStr;
                HttpReply.ecs = string.Empty;
                HttpReply.ecssign = string.Empty;
                return HttpReply;

            }
            catch (Exception ex)
            {
                HttpReply = HttpReplyNG.Trx(_replyProcessStep, ex);
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


        private bool Handle_CCREDREQ(string username, string devicetype)
        {
            //---暫時 Always Return True 以後有想到邏輯再補上
            return true;
        }


        private void GenerateCredential(string username)
        {
            Credential_Info credObj = ObjectManagerInstance.GetCredInfo(username);
            credObj.Nonce = 0;
            string credJsonStr = JsonSerializer.Serialize(credObj);
            string signOut = string.Empty;
            string Credential = string.Empty;
            if (SecurityManager.SIGNRSASecurity().SignString(credJsonStr, out signOut, out string returnMsgOut) == 0)
            {
                Credential Cred = new Credential();
                Cred.CredContent = credJsonStr;
                Cred.CredSign = signOut;
                this.ObjectManagerInstance.SetCredential(username, Cred);
            }

        }

    }
}
