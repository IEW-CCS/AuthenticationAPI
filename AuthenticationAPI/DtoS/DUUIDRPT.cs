using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class DUUIDRPT
    {
        public string DeviceUUIDJSon { get; set; }
        public string MobilePublicKey { get; set; }

        public DUUIDRPT()
        {

            DeviceUUIDJSon = string.Empty;
            MobilePublicKey = string.Empty;
        }

    }
}
