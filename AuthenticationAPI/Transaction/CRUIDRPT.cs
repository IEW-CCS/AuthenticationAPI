using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class CRUIDRPT
    {
        public string DeviceUUIDJSon { get; set; }
        public string MobilePublicKey { get; set; }

        public CRUIDRPT()
        {

            DeviceUUIDJSon = string.Empty;
            MobilePublicKey = string.Empty;
        }

    }
}
