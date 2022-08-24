using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class APREGREQ
    {
        public string UserName { get; set; }
        public string PassWord { get; set; }
        public string ClientRSAPublicKey { get; set; }
        public string APPGuid { get; set; }
        public string APPVersion { get; set; }
        public string OSEnv { get; set; }
        public DateTime TimeStamp { get; set; }

        public APREGREQ()
        {
            UserName = string.Empty;
            PassWord = string.Empty;
            ClientRSAPublicKey = string.Empty;
            APPGuid = string.Empty;
            APPVersion = string.Empty;
            OSEnv = string.Empty;
            TimeStamp = DateTime.Now;
        }

    }
}
