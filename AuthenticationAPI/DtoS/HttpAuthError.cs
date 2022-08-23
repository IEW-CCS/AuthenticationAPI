using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    enum HttpAuthErrorCode
    {
        UserNotExist = 1,        //App Regist Request
        ProcStepNotMatch = 2,
        DecryptError = 3,
        DeserializeError = 4,
        CheckAuthFailed = 5,
        ECSbyPublicKeyErrorRSA = 6,
        DecryptECSError = 7
    }
    public class HttpAuthError
    {
      
        public static string ErrorMsg(int code)
        {
            ErrorCodes.TryGetValue(code, out string ErrorMsg);
            return ErrorMsg;
        }

        private static readonly Dictionary<int, string> ErrorCodes = new Dictionary<int, string>
        {
              { 1, "User Not Exist" },
              { 2, "Process Step Not Match" },
              { 3, "Decrype Error" },
              { 4, "Deserialize Error" },
              { 5, "Authentication failed" },
              { 6, "Encrypt by Client Public Key Error (RSA)" },
              { 7, "Descrypt ECS by Private Key Error (RSA)" }

        };
    }
}
