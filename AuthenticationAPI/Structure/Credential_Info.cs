using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class Credential
    {
        public string CredContent { get; set; }
        public string CredSign { get; set; }
        public Credential()
        {
            CredContent = string.Empty;
            CredSign = string.Empty;
        }



    }
    public class Credential_Info
    {
        public string UserName { get; set; }
        public string APPGuid { get; set; }
        public string APPVersion { get; set; }
        public string DeviceUUID { get; set; }
        public int Nonce { get; set; }
        public DateTime CreateDateTime { get; set; }

        public Credential_Info()
        {
            UserName = string.Empty;
            APPGuid = string.Empty;
            APPVersion = string.Empty;
            DeviceUUID = string.Empty;
            Nonce = 0;
        }
    }
}
