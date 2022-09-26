using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class ARWSCANN
    {
       
        public string Credential { get; set; }
        public string SignedPublicKey { get; set; }
        public string DeviceUUID { get; set; }


        public ARWSCANN()
        {

            Credential = string.Empty;
            SignedPublicKey = string.Empty;
            DeviceUUID = string.Empty;
        }
    }
}
