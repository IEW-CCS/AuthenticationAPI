using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class APREGCMP
    {
        public string UserName { get; set; }
        public string DeviceUUID { get; set; }
        public string Result { get; set; }
        public DateTime TimeStamp { get; set; }

        public APREGCMP()
        {
            UserName = string.Empty;
            DeviceUUID = string.Empty;
            Result = string.Empty;
            TimeStamp = DateTime.Now;
        }
    }
}
