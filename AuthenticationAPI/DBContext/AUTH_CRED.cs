using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthenticationAPI.DBContext
{
    public class AUTH_CRED
    {
        public int id { get; set; }
        public string UserName { get; set; }
        public string APPGuid { get; set; }
        public string APPVersion { get; set; }
        public string DeviceUUID { get; set; }
        public int Nonce { get; set; }
        public DateTime CreateDateTime { get; set; }
    }
}
