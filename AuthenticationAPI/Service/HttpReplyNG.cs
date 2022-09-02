using AuthenticationAPI.DtoS;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.Service
{
    public static class HttpReplyNG
    {

        public static HttpTrx Trx(string processStep, int returnCode)
        {
            HttpTrx HttpReply = new HttpTrx();
            HttpReply.UserName = string.Empty;
            HttpReply.ProcStep = processStep;
            HttpReply.ReturnCode = returnCode;
            HttpReply.ReturnMsg = HttpAuthError.ErrorMsg(returnCode);
            HttpReply.DataContent = string.Empty;
            return HttpReply;
        }

        public static HttpTrx Trx(string processStep, int returnCode, string returnMsg)
        {
            HttpTrx HttpReply = new HttpTrx();
            HttpReply.UserName = string.Empty;
            HttpReply.ProcStep = processStep;
            HttpReply.ReturnCode = returnCode;
            HttpReply.ReturnMsg = returnMsg;
            HttpReply.DataContent = string.Empty;
            return HttpReply;
        }

        public static HttpTrx Trx (string processStep, Exception ex)
        {
            HttpTrx HttpReply = new HttpTrx();
            HttpReply.UserName = string.Empty;
            HttpReply.ProcStep = processStep;
            HttpReply.ReturnCode = 999;
            HttpReply.ReturnMsg = ex.Message;
            HttpReply.DataContent = string.Empty;
            return HttpReply;
        }
    }
}
