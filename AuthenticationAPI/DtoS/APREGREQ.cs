using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class APREGREQ
    {
        public string PassWord { get; set; }
        public string ClientRSAPublicKey { get; set; }
        public string DeviceMacAddress { get; set; }
        public string APPGuid { get; set; }
        public string APPVersion { get; set; }
        public string OSEnv { get; set; }

        public APREGREQ()
        { 
            PassWord = string.Empty;
            ClientRSAPublicKey = string.Empty;
            DeviceMacAddress = string.Empty;
            APPGuid = string.Empty;
            APPVersion = string.Empty;
            OSEnv = string.Empty;
        }

    }
}
