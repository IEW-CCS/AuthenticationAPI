using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class APVRYREQ
    {
        public string ServerName { get; set; }
        public string UserName { get; set; }
        public string PassWord { get; set; }
        public string APPGuid { get; set; }
        public string APPVersion { get; set; }
        public string OSEnv { get; set; }
        public DateTime TimeStamp { get; set; }

        public APVRYREQ()
        {
            ServerName = string.Empty;
            UserName = string.Empty;
            PassWord = string.Empty;
            APPGuid = string.Empty;
            APPVersion = string.Empty;
            OSEnv = string.Empty;
            TimeStamp = DateTime.Now;

        }
    }
}
