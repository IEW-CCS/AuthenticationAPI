using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    enum WSAuthErrorCode
    {
        TokenInfoError = 1,        
        ConnectError = 2,
        AuthorizedError = 3
    }
    public class WSAuthError
    {
        public static string ErrorMsg(int code)
        {
            ErrorCodes.TryGetValue(code, out string ErrorMsg);
            return ErrorMsg;
        }

        private static readonly Dictionary<int, string> ErrorCodes = new Dictionary<int, string>
        {
              { 1, "Token Information Error" },
              { 2, "Websocket Connect Error" },
              { 3, "Authorized Error" }

        };
    }
}
