using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class APREGREQ
    {
        public string ServerName { get; set; }
        public string UserName { get; set; }
        public string PassWord { get; set; }
        public string BlueToothMAC { get; set; }
        public string ClientRSAPublicKey { get; set; }
        public string APPGuid { get; set; }
        public string APPVersion { get; set; }
        public string OSEnv { get; set; }
        public DateTime TimeStamp { get; set; }

    }
}
