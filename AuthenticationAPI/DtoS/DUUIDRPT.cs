using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class DUUIDRPT
    {
        public string UserName { get; set; }
        public string DeviceUUID { get; set; }
        public string MobilePublicKey { get; set; }
        public DateTime TimeStamp { get; set; }

        public DUUIDRPT()
        {
            UserName = string.Empty;
            DeviceUUID = string.Empty;
            MobilePublicKey = string.Empty;
            TimeStamp = DateTime.Now;
        }

    }
}
