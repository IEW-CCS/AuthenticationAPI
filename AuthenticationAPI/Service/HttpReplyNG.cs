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
            HttpReply.username = string.Empty;
            HttpReply.procstep = processStep;
            HttpReply.returncode = returnCode ;
            HttpReply.returnmsg = HttpAuthError.ErrorMsg(returnCode);
            HttpReply.datacontent = string.Empty;
            return HttpReply;
        }

        public static HttpTrx Trx(string processStep, int returnCode, string returnMsg)
        {
            HttpTrx HttpReply = new HttpTrx();
            HttpReply.username = string.Empty;
            HttpReply.procstep = processStep;
            HttpReply.returncode = returnCode;
            HttpReply.returnmsg = returnMsg;
            HttpReply.datacontent = string.Empty;
            return HttpReply;
        }

        public static HttpTrx Trx (string processStep, Exception ex)
        {
            HttpTrx HttpReply = new HttpTrx();
            HttpReply.username = string.Empty;
            HttpReply.procstep = processStep;
            HttpReply.returncode = 999;
            HttpReply.returnmsg = ex.Message;
            HttpReply.datacontent = string.Empty;
            return HttpReply;
        }
    }
}
