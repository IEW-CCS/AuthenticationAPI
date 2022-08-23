using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DtoS
{
    public class DUUIDANN
    {
        public string ServerName { get; set; }
        public string UserName { get; set; }
        public string DeviceUUID { get; set; }
        public DateTime TimeStamp { get; set; }
    }
}
